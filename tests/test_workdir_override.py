"""Unit tests for ``agentbox.cli._validate_container_workdir``.

The launcher accepts a user-supplied container workdir override
(``--workdir`` CLI flag or ``workdir:`` config key). This module
covers the validation rules: must be an absolute POSIX path, can't
be ``/``, and can't shadow paths agentbox already bind-mounts
internally (``/home/agentbox``, ``/etc/claude-code``,
``/usr/local/share/ca-certificates``).

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox.cli import _validate_container_workdir


class ValidateContainerWorkdirTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    def test_simple_absolute_path(self) -> None:
        self.assertEqual(_validate_container_workdir("/app"), "/app")

    def test_nested_absolute_path(self) -> None:
        self.assertEqual(
            _validate_container_workdir("/workspace/myproj"),
            "/workspace/myproj",
        )

    def test_trailing_slash_is_stripped(self) -> None:
        self.assertEqual(_validate_container_workdir("/app/"), "/app")

    def test_default_mirror_root_prefix_allowed(self) -> None:
        # /agentbox/<...> is the default scheme but a user is free to
        # pin a specific override under it too.
        self.assertEqual(
            _validate_container_workdir("/agentbox/foo"),
            "/agentbox/foo",
        )

    # ------------------------------------------------------------------
    # Rejections
    # ------------------------------------------------------------------

    def test_empty_string_errors(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _validate_container_workdir("")
        self.assertIn("non-empty string", str(cm.exception))

    def test_relative_path_errors(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _validate_container_workdir("app")
        self.assertIn("absolute POSIX path", str(cm.exception))

    def test_root_errors(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _validate_container_workdir("/")
        self.assertIn("cannot be '/'", str(cm.exception))

    def test_home_agentbox_root_errors(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _validate_container_workdir("/home/agentbox")
        self.assertIn("internal mount", str(cm.exception))

    def test_home_agentbox_subpath_errors(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _validate_container_workdir("/home/agentbox/.claude")
        self.assertIn("internal mount", str(cm.exception))

    def test_etc_claude_code_errors(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _validate_container_workdir("/etc/claude-code/foo")
        self.assertIn("internal mount", str(cm.exception))

    def test_ca_dir_errors(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            _validate_container_workdir(
                "/usr/local/share/ca-certificates"
            )
        self.assertIn("internal mount", str(cm.exception))

    def test_lookalike_prefix_is_allowed(self) -> None:
        # /home/agentbox-other is not under /home/agentbox; only the
        # exact match or a real subpath should be rejected.
        self.assertEqual(
            _validate_container_workdir("/home/agentbox-other"),
            "/home/agentbox-other",
        )


if __name__ == "__main__":
    unittest.main()
