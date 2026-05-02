# pyright: reportAttributeAccessIssue=false
#
# This script runs only inside the Linux sidecar container; it uses
# Linux-only os attributes (chown, setgroups, setgid, setuid,
# geteuid) that pyright on Windows/macOS doesn't see in its stdlib
# stubs. Suppress at the file level rather than scattering inline
# ignores.
"""Sidecar entrypoint: configure netns, drop privileges, run mitmproxy.

# Why this runs as root

Installing iptables NAT rules requires ``CAP_NET_ADMIN`` against the
sidecar's network namespace. Capabilities only attach to UID 0 by
default; granting them to a non-root user via ``setcap`` is silently
defeated by ``--security-opt=no-new-privileges`` (file capabilities
are stripped on exec under no_new_privs). So the entrypoint must
boot as root in order to install the iptables rules.

That "root" is heavily constrained, though. The launcher starts the
sidecar with::

    --cap-drop=ALL --cap-add=NET_ADMIN --cap-add=SETUID --cap-add=SETGID
    --security-opt=no-new-privileges

So root inside the sidecar has only three caps: install iptables
rules (``NET_ADMIN``) and drop privileges (``SETUID``/``SETGID``).
No mount, no chroot, no kernel modules, no raw sockets, no setuid
binaries can elevate. ``no-new-privileges`` blocks any escalation
that survives the cap drop.

After the iptables setup the entrypoint drops to UID 4242
(``mitmproxy``) for the long-running mitmproxy process. The brief
root window is bounded to the three iptables calls.

The sidecar is the proxy's trust boundary regardless: it holds the
real GitHub PAT and the mitmproxy CA private key. Any code running
inside this container is trusted by definition. The actual
hostile-code boundary is the *agent* container, which the launcher
runs as ``--user agentbox`` (UID 1000) with ``--cap-drop=ALL`` and
``--security-opt=no-new-privileges`` -- zero capabilities.

# Sequence

1. Disable IPv6 in the netns. Our iptables rules are IPv4-only;
   without this, v6 connections from the agent would bypass.
2. Install iptables NAT OUTPUT rules:
   - exempt UID 4242 from REDIRECT so mitmproxy's own upstream
     traffic doesn't loop back into itself,
   - REDIRECT TCP/80 + TCP/443 to mitmproxy's transparent listener
     on port 8080,
   - REDIRECT UDP/53 to the DNS sinkhole on port 5353 (the sinkhole
     binds a non-privileged port so it doesn't need
     ``CAP_NET_BIND_SERVICE``).
3. Pre-create ``/run/agentbox`` owned by mitmproxy so the dropped
   process can write the readiness sentinel later.
4. Drop privileges to UID/GID 4242 via ``os.setgid`` + ``os.setuid``.
5. Spawn the DNS sinkhole as a child Popen.
6. Spawn mitmdump in transparent mode.
7. Wait for mitmproxy to start listening, then touch
   ``/run/agentbox/proxy-ready``. The launcher polls this via
   ``docker exec`` to know when the agent can start.
8. Forward SIGTERM/SIGINT to children. Container exits when
   mitmproxy exits.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import FrameType

_MITMPROXY_UID = 4242
_MITMPROXY_GID = 4242
_PROXY_PORT = 8080
_DNS_PORT = 5353
_DNS_SCRIPT = "/opt/agentbox/dns.py"
_READY_PATH = Path("/run/agentbox/proxy-ready")
_WORKDIR = Path("/agentbox/proxy")


def _disable_ipv6() -> None:
    """Take IPv6 out of the picture so iptables-only filtering is complete.

    Our redirect rules are IPv4-only. If the netns has working IPv6
    (uncommon on Docker default bridge but possible on user-defined
    networks), agent connections to literal v6 destinations would
    bypass everything. The DNS sinkhole's NXDOMAIN-on-AAAA mitigates
    most paths -- resolvers fall back to A -- but a hardcoded
    ``[2001:...]:443`` would still leak.

    Disabling v6 at the netns level closes that. Per-netns sysctl,
    so it only affects this sidecar's netns (which the agent shares).

    Requires ``CAP_NET_ADMIN``, which the entrypoint already holds.
    Failures (e.g. an image without IPv6 support compiled in) are
    logged but not fatal -- if v6 isn't there in the first place
    there's nothing to disable.
    """
    for key in (
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    ):
        try:
            with open(key, "w") as f:
                f.write("1\n")
        except OSError as exc:
            print(
                f"agentbox-sidecar: could not disable ipv6 via {key} "
                f"({exc}); continuing with iptables-only enforcement",
                flush=True,
            )


def _run_iptables(*args: str) -> None:
    cmd = ["iptables", "-t", "nat", *args]
    print(f"agentbox-sidecar: $ {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd)


def _setup_iptables() -> None:
    # Order matters: the --uid-owner RETURN must come first so
    # mitmproxy's own outbound traffic to upstream isn't caught by
    # the REDIRECT rules below (which would create a loop).
    _run_iptables(
        "-A", "OUTPUT",
        "-m", "owner", "--uid-owner", str(_MITMPROXY_UID),
        "-j", "RETURN",
    )
    for dport in ("80", "443"):
        _run_iptables(
            "-A", "OUTPUT",
            "-p", "tcp", "--dport", dport,
            "-j", "REDIRECT", "--to-port", str(_PROXY_PORT),
        )
    # DNS goes to a non-privileged port (5353) so the sinkhole can
    # bind it as the unprivileged mitmproxy user. Without this
    # redirect we'd need CAP_NET_BIND_SERVICE just to listen on 53.
    _run_iptables(
        "-A", "OUTPUT",
        "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-port", str(_DNS_PORT),
    )


def _prepare_runtime_dir() -> None:
    """Create /run/agentbox owned by mitmproxy before we drop privileges."""
    _READY_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chown(_READY_PATH.parent, _MITMPROXY_UID, _MITMPROXY_GID)


def _drop_privileges() -> None:
    """Drop UID/GID to mitmproxy. Requires CAP_SETUID + CAP_SETGID.

    Without these caps the kernel returns EPERM on the setuid
    syscall (root → non-root transitions need CAP_SETUID even when
    decreasing privilege). We surface that as a friendly diagnostic
    instead of a bare PermissionError stack trace.
    """
    try:
        os.setgroups([])
        os.setgid(_MITMPROXY_GID)
        os.setuid(_MITMPROXY_UID)
    except PermissionError as exc:
        sys.exit(
            "agentbox-sidecar: failed to drop privileges via "
            f"setuid/setgid ({exc}). The launcher must pass "
            "--cap-add=SETUID --cap-add=SETGID for this to work "
            "under --cap-drop=ALL."
        )
    # Defensive post-check in case a future kernel ever lets a
    # partial transition through silently.
    if os.geteuid() == 0:
        sys.exit(
            "agentbox-sidecar: setuid returned success but euid is "
            "still 0; refusing to run privileged."
        )


def _wait_for_proxy_ready(host: str = "127.0.0.1", port: int = _PROXY_PORT,
                          timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    creds = _WORKDIR / "credentials.json"
    allowlist = _WORKDIR / "allowlist.yaml"
    github_policy = _WORKDIR / "github.json"
    for p in (creds, allowlist, github_policy):
        if not p.is_file():
            sys.exit(f"agentbox-sidecar: missing {p}")

    # --- privileged setup ---
    _disable_ipv6()
    _setup_iptables()
    _prepare_runtime_dir()

    # --- drop to UID 4242 for the rest of the lifetime ---
    _drop_privileges()

    # --- everything below runs as mitmproxy ---
    dns_proc = subprocess.Popen(
        [sys.executable, _DNS_SCRIPT],
        stdout=sys.stdout, stderr=sys.stderr,
    )

    # Optional: e2e-test mock-llm script staged by the launcher into
    # the bind-mounted workdir. Inert when absent (production path).
    mock_llm_script = _WORKDIR / "mock_llm.py"
    proxy_cmd = [
        sys.executable, "-m", "agentbox.proxy",
        "--transparent",
        "--port", str(_PROXY_PORT),
        "--credentials", str(creds),
        "--allowlist", str(allowlist),
        "--github-policy", str(github_policy),
    ]
    if mock_llm_script.is_file():
        proxy_cmd += ["--mock-llm", str(mock_llm_script)]
    proxy_proc = subprocess.Popen(
        proxy_cmd,
        stdout=sys.stdout, stderr=sys.stderr,
    )

    if not _wait_for_proxy_ready():
        proxy_proc.terminate()
        dns_proc.terminate()
        sys.exit(
            "agentbox-sidecar: mitmproxy did not start listening on "
            f"127.0.0.1:{_PROXY_PORT} within timeout"
        )

    _READY_PATH.touch()
    print(
        f"agentbox-sidecar: ready (mitmproxy on :{_PROXY_PORT}, "
        f"dns on :{_DNS_PORT}, running as uid {os.geteuid()})",
        flush=True,
    )

    def _on_signal(signum: int, frame: FrameType | None) -> None:
        proxy_proc.terminate()
        dns_proc.terminate()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    rc = proxy_proc.wait()
    dns_proc.terminate()
    try:
        dns_proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        dns_proc.kill()
    sys.exit(rc)


if __name__ == "__main__":
    main()
