"""Unit tests for the network-mode launcher branching.

Three things are pinned:

1. Permissive mode (default) injects ``HTTPS_PROXY`` / ``HTTP_PROXY`` /
   ``NO_PROXY`` into the agent docker run argv and does NOT use
   ``--network container:`` -- this is the "host-subprocess proxy"
   path.
2. Transparent-shared mode uses ``--network container:<sidecar>``,
   omits the proxy env vars, and skips the
   ``--add-host=host.docker.internal:host-gateway`` workaround
   (which is only meaningful when the agent reaches back to the
   host).
3. Transparent-isolated mode exits early in ``_main`` with the
   friendly "not yet supported" message before any docker activity.

The proxy/handler/allowlist code is unchanged across modes; this
file does not re-test it.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox import cli


class _FakeProc:
    """subprocess.Popen stand-in: exits cleanly on first poll."""

    def __init__(self, cmd: list[str]) -> None:
        self.captured_cmd: list[str] = list(cmd)
        self.pid = 1
        self.returncode = 0
        self.stdout = None

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass


def _capture_run_agent_cmd(
    network_mode: str, sidecar_name: str | None,
) -> list[str]:
    """Invoke ``_run_agent`` with subprocess + filesystem patched.

    Returns the docker-run argv ``_run_agent`` built. The mocked Popen
    exits immediately so the polling loop terminates after one tick.
    """
    captured: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):
        captured.append(list(cmd))
        return _FakeProc(cmd)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        workdir = tmp_path / "work"
        workdir.mkdir()
        ca_path = tmp_path / "ca.crt"
        ca_path.write_text("dummy", encoding="utf-8")

        prev_cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            with (
                mock.patch.object(Path, "home", return_value=fake_home),
                mock.patch("agentbox.cli.subprocess.Popen", side_effect=_fake_popen),
                mock.patch("agentbox.cli._is_docker_desktop", return_value=True),
                # Silence the rich-formatted launcher banner so test
                # output stays terse.
                mock.patch("agentbox.cli._console"),
                mock.patch("agentbox.cli._step"),
            ):
                cli._run_agent(
                    mode="shell",
                    port=8888,
                    surrogate="ghp_AGENTBOX_SURROGATE_test",
                    real_token="",
                    ca_path=ca_path,
                    mode_args=[],
                    image_tag="agentbox-base:local",
                    workdir=workdir,
                    network_mode=network_mode,
                    sidecar_name=sidecar_name,
                )
        finally:
            os.chdir(prev_cwd)

    assert captured, "no docker invocation was captured"
    return captured[0]


def _has_env(cmd: list[str], prefix: str) -> bool:
    """True if some `-e PREFIX...` pair appears in ``cmd``."""
    return any(
        cmd[i] == "-e" and cmd[i + 1].startswith(prefix)
        for i in range(len(cmd) - 1)
    )


class PermissiveDockerCmdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cmd = _capture_run_agent_cmd("permissive", sidecar_name=None)

    def test_includes_https_proxy_env(self) -> None:
        self.assertTrue(_has_env(self.cmd, "HTTPS_PROXY="))
        self.assertTrue(_has_env(self.cmd, "HTTP_PROXY="))
        self.assertTrue(_has_env(self.cmd, "NO_PROXY="))

    def test_proxy_url_points_at_host_internal(self) -> None:
        # Find the value paired with -e HTTPS_PROXY.
        idx = self.cmd.index("HTTPS_PROXY=http://host.docker.internal:8888")
        self.assertEqual(self.cmd[idx - 1], "-e")

    def test_no_network_container_flag(self) -> None:
        # --network is reserved for transparent-shared.
        self.assertNotIn("--network", self.cmd)

    def test_does_not_pass_sidecar_name(self) -> None:
        # No "container:agentbox-proxy-..." anywhere in the argv.
        self.assertFalse(
            any(c.startswith("container:") for c in self.cmd),
            f"unexpected container: token in permissive cmd: {self.cmd}",
        )


class TransparentSharedDockerCmdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sidecar = "agentbox-proxy-1234"
        self.cmd = _capture_run_agent_cmd(
            "transparent-shared", sidecar_name=self.sidecar,
        )

    def test_uses_network_container_flag(self) -> None:
        self.assertIn("--network", self.cmd)
        idx = self.cmd.index("--network")
        self.assertEqual(self.cmd[idx + 1], f"container:{self.sidecar}")

    def test_omits_https_proxy_env(self) -> None:
        self.assertFalse(_has_env(self.cmd, "HTTPS_PROXY="))
        self.assertFalse(_has_env(self.cmd, "HTTP_PROXY="))
        self.assertFalse(_has_env(self.cmd, "NO_PROXY="))

    def test_keeps_ca_env_vars(self) -> None:
        # CA trust still matters: the sidecar's mitmproxy still
        # terminates TLS with the agentbox CA.
        self.assertTrue(_has_env(self.cmd, "NODE_EXTRA_CA_CERTS="))
        self.assertTrue(_has_env(self.cmd, "GIT_SSL_CAINFO="))
        self.assertTrue(_has_env(self.cmd, "REQUESTS_CA_BUNDLE="))

    def test_no_add_host_workaround(self) -> None:
        # host.docker.internal isn't reachable from the agent's netns
        # in transparent-shared (it's the sidecar's netns), so the
        # add-host workaround would be misleading -- launcher must
        # skip it.
        self.assertFalse(
            any("--add-host" in c for c in self.cmd),
            f"unexpected --add-host in transparent-shared cmd: {self.cmd}",
        )

    def test_missing_sidecar_name_is_internal_error(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _capture_run_agent_cmd("transparent-shared", sidecar_name=None)
        self.assertIn("internal error", str(cm.exception))


class StageSidecarFilesTests(unittest.TestCase):
    """The chmod + CA-staging step that lets the sidecar UID 4242 read its inputs.

    Mode-checking assertions are skipped on Windows: ``os.chmod`` there
    only toggles the read-only bit, so the 0o755/0o644 semantics we
    rely on at runtime (Linux container) aren't observable from a
    Windows host. The functional fix is unchanged; we just can't
    verify it here.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agentbox-stage-")
        self.tmp = Path(self._tmp.name)
        self.workdir = self.tmp / "workdir"
        self.workdir.mkdir(mode=0o700)
        # Stand in for the launcher-written session files.
        for fname in ("credentials.json", "allowlist.yaml", "github.json"):
            (self.workdir / fname).write_text("{}", encoding="utf-8")
            (self.workdir / fname).chmod(0o600)
        # Stand in for the host's mitmproxy CA dir.
        self.ca_dir = self.tmp / "mitmproxy"
        self.ca_dir.mkdir()
        self.ca_path = self.ca_dir / "mitmproxy-ca-cert.pem"
        self.ca_path.write_text("dummy cert", encoding="utf-8")
        (self.ca_dir / "mitmproxy-ca.pem").write_text(
            "dummy key", encoding="utf-8",
        )
        (self.ca_dir / "mitmproxy-ca.pem").chmod(0o600)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_returns_staged_dir_with_ca_files(self) -> None:
        staged = cli._stage_sidecar_files(self.workdir, self.ca_path)
        self.assertEqual(staged, self.workdir / "mitmproxy-ca")
        self.assertTrue((staged / "mitmproxy-ca.pem").exists())
        self.assertTrue((staged / "mitmproxy-ca-cert.pem").exists())

    @unittest.skipIf(sys.platform == "win32", "chmod is a no-op on Windows")
    def test_workdir_is_chmod_to_traversable(self) -> None:
        cli._stage_sidecar_files(self.workdir, self.ca_path)
        # 0o755 = rwxr-xr-x; the sidecar's UID 4242 needs at least
        # the +x on others to traverse into the directory.
        mode = self.workdir.stat().st_mode & 0o777
        self.assertEqual(mode, 0o755)

    @unittest.skipIf(sys.platform == "win32", "chmod is a no-op on Windows")
    def test_session_files_become_world_readable(self) -> None:
        cli._stage_sidecar_files(self.workdir, self.ca_path)
        for fname in ("credentials.json", "allowlist.yaml", "github.json"):
            mode = (self.workdir / fname).stat().st_mode & 0o777
            self.assertEqual(mode, 0o644, f"{fname} mode = {oct(mode)}")

    @unittest.skipIf(sys.platform == "win32", "chmod is a no-op on Windows")
    def test_ca_copy_is_world_readable_not_original(self) -> None:
        cli._stage_sidecar_files(self.workdir, self.ca_path)
        # The host's CA private key must keep its 0o600 mode -- we
        # only relax the per-session copy, not the long-lived
        # original under ~/.mitmproxy/.
        original_key = self.ca_dir / "mitmproxy-ca.pem"
        self.assertEqual(
            original_key.stat().st_mode & 0o777, 0o600,
            "stage_sidecar_files must not touch the host CA private key",
        )
        copy_key = self.workdir / "mitmproxy-ca" / "mitmproxy-ca.pem"
        self.assertEqual(copy_key.stat().st_mode & 0o777, 0o644)

    def test_missing_ca_file_exits_cleanly(self) -> None:
        # Remove the public cert so the staging step fails.
        self.ca_path.unlink()
        with self.assertRaises(SystemExit) as cm:
            cli._stage_sidecar_files(self.workdir, self.ca_path)
        self.assertIn("missing CA file", str(cm.exception))


class TransparentIsolatedBailTests(unittest.TestCase):
    """Selecting transparent-isolated must exit before any docker activity."""

    def test_main_bails_with_friendly_message(self) -> None:
        # cd into a tempdir so no agentbox.config.yaml is picked up.
        with tempfile.TemporaryDirectory() as tmp:
            prev = Path.cwd()
            os.chdir(tmp)
            try:
                # If the early-bail were missing, _main would proceed
                # to call _ensure_image, which shells out to docker
                # and would fail in this test environment. That
                # failure mode is not what we're testing -- we want
                # to confirm the bail short-circuits before that.
                with mock.patch("agentbox.cli._ensure_image") as ensure:
                    with self.assertRaises(SystemExit) as cm:
                        cli._main([
                            "--network", "transparent-isolated", "shell",
                        ])
                    ensure.assert_not_called()
                self.assertIn(
                    "transparent-isolated", str(cm.exception),
                )
                self.assertIn("not yet supported", str(cm.exception))
            finally:
                os.chdir(prev)


if __name__ == "__main__":
    unittest.main()
