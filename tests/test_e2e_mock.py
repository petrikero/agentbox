"""End-to-end agentbox tests with a scripted mock LLM.

These actually start a Docker container, run the real ``pi`` /
``claude`` binaries inside, and route their LLM calls through the
agentbox proxy with the ``mock_llm`` addon swapping replies. The
goal is to pin the full launcher → proxy → agent → output-parser
flow with no network and no API key.

# How to run

These run by default as part of ``python -m unittest discover
tests``. The whole module self-skips with a clear reason when its
prerequisites aren't satisfied:

- Docker daemon isn't reachable, OR
- ``agentbox-base:local`` can't be built (e.g. no internet for the
  initial layer fetch).

For a fast inner loop -- skipping e2e even when Docker is up --
set ``AGENTBOX_E2E_SKIP=1`` in the environment, or use the
``Makefile``'s ``test-fast`` target.

Failure ergonomics: when an assertion in a test fails, the captured
stdout, stderr, and the mock-llm transcript are dumped to stderr.
A failure that exits with rc=1 and no message means the test
infrastructure itself is broken; an assertion failure carries the
full agent transcript with it.

# Setup model

``setUpModule`` does two things once per test session:

1. Probes Docker (``docker info``).
2. Builds ``agentbox-base:local`` if its inputs (Dockerfile + bashrc)
   have changed since the last build, gated by a SHA-256 sentinel
   at ``~/.cache/agentbox/e2e-base-sha``. Most runs hit the cache
   and skip the docker invocation entirely.

Each test gets its own per-test tmpdir as the host cwd that the
launcher mounts into the container, plus its own mock-llm
transcript inside that tmpdir.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
sys.path.insert(0, str(_SRC))

_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "mock_scripts"
_TIMEOUT_S = int(os.environ.get("AGENTBOX_E2E_TIMEOUT", "180"))
_BASE_IMAGE_TAG = "agentbox-base:local"
_BASE_DOCKERFILE_DIR = _SRC / "agentbox" / "sandbox"


def _docker_available() -> tuple[bool, str]:
    """Probe the Docker daemon. Returns ``(ok, reason_when_not_ok)``."""
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except FileNotFoundError:
        return False, "docker CLI not on PATH"
    except subprocess.TimeoutExpired:
        return False, "`docker info` timed out (daemon hung?)"
    if proc.returncode != 0:
        snippet = (proc.stderr or proc.stdout or "").strip().splitlines()
        first = snippet[0] if snippet else "(no output)"
        return False, f"`docker info` failed: {first}"
    return True, ""


def _hash_inputs(paths: list[Path]) -> str:
    """SHA-256 of all provided file contents, in path order. Stable across runs."""
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(p.name.encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _ensure_base_image() -> None:
    """Build ``agentbox-base:local`` once per Dockerfile change.

    Docker's layer cache keeps a no-op rebuild fast, but the docker CLI
    invocation is still ~1s. We cut that with a content-hash sentinel:
    if the inputs are unchanged AND the image is still present, the
    build is skipped entirely. First test in a fresh checkout pays the
    full build; everything afterwards is free.

    A failure to build is reported as a test-skip, not a test-fail --
    the e2e suite isn't gating on the image being buildable, only on it
    actually being usable when it is.
    """
    inputs = [_BASE_DOCKERFILE_DIR / name for name in ("Dockerfile", "bashrc")]
    for p in inputs:
        if not p.is_file():
            raise unittest.SkipTest(f"e2e: missing build input {p}")
    expected_sha = _hash_inputs(inputs)

    cache_dir = Path.home() / ".cache" / "agentbox"
    cache_dir.mkdir(parents=True, exist_ok=True)
    sha_file = cache_dir / "e2e-base-sha"

    if sha_file.is_file() and sha_file.read_text("utf-8").strip() == expected_sha:
        # Cache says we're current. Confirm the image actually exists --
        # the user may have run `docker rmi` since the last build.
        check = subprocess.run(
            ["docker", "image", "inspect", _BASE_IMAGE_TAG],
            capture_output=True, check=False,
        )
        if check.returncode == 0:
            return

    print(
        f"\n[e2e] building {_BASE_IMAGE_TAG} (one-time per Dockerfile change)...",
        flush=True,
    )
    proc = subprocess.run(
        ["docker", "build", "-t", _BASE_IMAGE_TAG, str(_BASE_DOCKERFILE_DIR)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or proc.stdout or "").splitlines()[-20:])
        raise unittest.SkipTest(
            f"e2e: failed to build {_BASE_IMAGE_TAG} "
            f"(rc={proc.returncode}). Output tail:\n{tail}"
        )
    sha_file.write_text(expected_sha, encoding="utf-8")


def setUpModule() -> None:
    """Probe Docker + warm the base image before any test runs.

    On any prerequisite failure we ``raise unittest.SkipTest`` so the
    whole module is reported as skipped with a clear reason -- one
    skip line at the top of the run rather than a quiet env-var gate.
    """
    if os.environ.get("AGENTBOX_E2E_SKIP") == "1":
        raise unittest.SkipTest(
            "AGENTBOX_E2E_SKIP=1 (opt-out for fast inner-loop iteration)"
        )
    ok, reason = _docker_available()
    if not ok:
        raise unittest.SkipTest(
            f"e2e tests need a running Docker daemon ({reason})"
        )
    _ensure_base_image()


def _seed_cwd(tmp: Path) -> None:
    (tmp / "README.md").write_text(
        "# demo\nA tiny project used by the agentbox e2e tests.\n",
        encoding="utf-8",
    )


def _run_agentbox(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    """Run the launcher via ``python -m agentbox.cli``.

    Uses the test interpreter so the working tree's source is what
    gets exercised -- no dependency on a separately-installed
    ``agentbox`` binary on PATH. Each call is a fresh subprocess so
    the launcher's ``atexit`` handlers fire (proxy terminated,
    workdir cleaned up); running ``cli.main()`` in-process leaks
    those across tests.
    """
    return subprocess.run(
        [sys.executable, "-m", "agentbox.cli", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_S,
        check=False,
    )


def _dump_diag(
    result: subprocess.CompletedProcess,
    transcript: Path,
) -> None:
    """Print captured agentbox state to stderr after an assertion failure.

    The test harness calls this from a ``try/except`` wrapper around
    each test body, then re-raises -- so the AssertionError text and
    the captured state arrive together.
    """
    print("\n=== agentbox: returncode ===", file=sys.stderr)
    print(result.returncode, file=sys.stderr)
    print("\n=== agentbox: stdout ===", file=sys.stderr)
    print(result.stdout or "(empty)", file=sys.stderr)
    print("\n=== agentbox: stderr ===", file=sys.stderr)
    print(result.stderr or "(empty)", file=sys.stderr)
    if transcript.is_file():
        body = transcript.read_text("utf-8")
        print("\n=== mock-llm transcript ===", file=sys.stderr)
        print(body or "(empty)", file=sys.stderr)
    else:
        print(
            f"\n=== mock-llm transcript: {transcript} not written ===",
            file=sys.stderr,
        )


class ClaudeMockE2ETest(unittest.TestCase):
    """Drive ``agentbox claude -- -p ...`` with a scripted LLM."""

    def test_print_mode_returns_scripted_final_answer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agentbox-e2e-") as tmp:
            cwd = Path(tmp)
            _seed_cwd(cwd)
            transcript = cwd / "transcript.jsonl"
            script = _FIXTURES / "claude_simple.py"

            result = _run_agentbox(
                # Launcher flags MUST precede the `mode` positional --
                # `mode_args` is argparse.REMAINDER and would otherwise
                # swallow `--mock-llm` etc. as args to the agent itself.
                # The host cwd comes from subprocess(cwd=...) above; the
                # launcher mirrors it under /agentbox/ in the container.
                "--mock-llm", str(script),
                "--mock-llm-transcript", str(transcript),
                "claude",
                "--",
                "-p", "summarise this repo",
                cwd=cwd,
            )

            try:
                self.assertEqual(
                    result.returncode, 0,
                    "agentbox claude exited non-zero",
                )
                self.assertIn("agentbox", result.stdout.lower())
                self.assertTrue(
                    transcript.is_file(),
                    "mock-llm transcript was not written",
                )
                entries = [
                    json.loads(line)
                    for line in transcript.read_text("utf-8").splitlines()
                    if line.strip()
                ]
                self.assertGreaterEqual(len(entries), 2)
                self.assertEqual(entries[0]["host"], "api.anthropic.com")
                stop_reasons = [e["reply"].get("stop_reason") for e in entries]
                self.assertIn("end_turn", stop_reasons)
            except Exception:
                _dump_diag(result, transcript)
                raise


@unittest.skip(
    "pi-coding-agent is built on Node.js undici, which does not honor "
    "HTTPS_PROXY -- requests bypass the host-subprocess proxy entirely "
    "in permissive mode and the mock-llm addon never sees them. "
    "Re-enable once the e2e harness supports transparent-shared mode "
    "with a writable transcript mount (the sidecar's /agentbox/proxy "
    "bind is read-only today)."
)
class PiMockE2ETest(unittest.TestCase):
    """Drive ``agentbox pi -- -p ...`` with a scripted LLM."""

    def test_print_mode_returns_scripted_final_answer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agentbox-e2e-") as tmp:
            cwd = Path(tmp)
            _seed_cwd(cwd)
            transcript = cwd / "transcript.jsonl"
            script = _FIXTURES / "pi_simple.py"

            result = _run_agentbox(
                # Launcher flags MUST precede the `mode` positional --
                # `mode_args` is argparse.REMAINDER (see ClaudeMockE2ETest).
                "--mock-llm", str(script),
                "--mock-llm-transcript", str(transcript),
                "pi",
                "--",
                "-p", "summarise this repo",
                cwd=cwd,
            )

            try:
                self.assertEqual(
                    result.returncode, 0,
                    "agentbox pi exited non-zero",
                )
                self.assertIn("agentbox", result.stdout.lower())
                self.assertTrue(
                    transcript.is_file(),
                    "mock-llm transcript was not written",
                )
                entries = [
                    json.loads(line)
                    for line in transcript.read_text("utf-8").splitlines()
                    if line.strip()
                ]
                self.assertGreaterEqual(len(entries), 1)
                self.assertEqual(entries[0]["host"], "api.anthropic.com")
            except Exception:
                _dump_diag(result, transcript)
                raise


if __name__ == "__main__":
    unittest.main()
