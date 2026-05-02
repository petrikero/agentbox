"""Unit tests for ``agentbox.cli._host_to_container_path``.

Each project agentbox launches gets its own container path under
``/agentbox`` (mirroring the host path) so per-cwd state doesn't
collide across projects. This covers the host-to-container mapping
helper.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import PurePosixPath, PureWindowsPath

_SRC = __import__("pathlib").Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox.cli import _CONTAINER_MOUNT_ROOT, _host_to_container_path


class HostToContainerPathTests(unittest.TestCase):
    def test_windows_drive_letter(self) -> None:
        self.assertEqual(
            _host_to_container_path(PureWindowsPath("C:\\code\\agentbox")),
            "/agentbox/c/code/agentbox",
        )

    def test_windows_lowercases_only_drive(self) -> None:
        # Subdir case is preserved; only the drive letter is lowercased.
        self.assertEqual(
            _host_to_container_path(PureWindowsPath("C:\\Users\\Petri\\Proj")),
            "/agentbox/c/Users/Petri/Proj",
        )

    def test_windows_drive_root(self) -> None:
        self.assertEqual(
            _host_to_container_path(PureWindowsPath("C:\\")),
            "/agentbox/c",
        )

    def test_posix_absolute(self) -> None:
        self.assertEqual(
            _host_to_container_path(PurePosixPath("/home/user/proj")),
            "/agentbox/home/user/proj",
        )

    def test_posix_root(self) -> None:
        self.assertEqual(
            _host_to_container_path(PurePosixPath("/")),
            _CONTAINER_MOUNT_ROOT,
        )

    def test_other_drive_letter(self) -> None:
        self.assertEqual(
            _host_to_container_path(PureWindowsPath("D:\\Projects\\X")),
            "/agentbox/d/Projects/X",
        )


if __name__ == "__main__":
    unittest.main()
