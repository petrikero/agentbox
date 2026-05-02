"""Unit tests for GitHub remote URL parsing.

Covers ``_parse_github_remote_url`` -- the pure function the launcher
uses to extract ``owner/name`` from the cwd's ``git remote get-url
origin`` output. Subprocess plumbing in ``_detect_cwd_github_repo``
is left to integration; this file pins the URL grammar.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox._shared import _parse_github_remote_url


class ParseGithubRemoteUrlTests(unittest.TestCase):
    def test_https_with_dot_git(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("https://github.com/foo/bar.git"),
            "foo/bar",
        )

    def test_https_without_dot_git(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("https://github.com/foo/bar"),
            "foo/bar",
        )

    def test_https_with_trailing_slash(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("https://github.com/foo/bar/"),
            "foo/bar",
        )

    def test_http_scheme_accepted(self) -> None:
        # Rare but valid; we accept either.
        self.assertEqual(
            _parse_github_remote_url("http://github.com/foo/bar.git"),
            "foo/bar",
        )

    def test_scp_like_ssh_with_dot_git(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("git@github.com:foo/bar.git"),
            "foo/bar",
        )

    def test_scp_like_ssh_without_dot_git(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("git@github.com:foo/bar"),
            "foo/bar",
        )

    def test_ssh_url_form(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("ssh://git@github.com/foo/bar.git"),
            "foo/bar",
        )

    def test_ssh_url_with_port(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("ssh://git@github.com:22/foo/bar.git"),
            "foo/bar",
        )

    def test_owner_with_hyphen(self) -> None:
        self.assertEqual(
            _parse_github_remote_url("https://github.com/my-org/repo.git"),
            "my-org/repo",
        )

    def test_repo_with_dot(self) -> None:
        # GitHub allows dots in repo names. The lazy ``[^/]+?`` plus
        # optional ``.git`` suffix means we strip only the trailing
        # ``.git``, not earlier dots in the name.
        self.assertEqual(
            _parse_github_remote_url("https://github.com/foo/bar.baz.git"),
            "foo/bar.baz",
        )

    def test_empty_string_returns_none(self) -> None:
        self.assertIsNone(_parse_github_remote_url(""))

    def test_whitespace_only_returns_none(self) -> None:
        self.assertIsNone(_parse_github_remote_url("   \n  "))

    def test_other_host_returns_none(self) -> None:
        self.assertIsNone(
            _parse_github_remote_url("https://gitlab.com/foo/bar.git"),
        )

    def test_enterprise_github_returns_none(self) -> None:
        # github.example.com is an enterprise install, not github.com.
        # We deliberately don't try to detect those -- the user's PAT
        # for github.com wouldn't help anyway.
        self.assertIsNone(
            _parse_github_remote_url(
                "https://github.example.com/foo/bar.git"
            ),
        )

    def test_garbage_input_returns_none(self) -> None:
        self.assertIsNone(_parse_github_remote_url("not a url"))

    def test_input_is_stripped_of_surrounding_whitespace(self) -> None:
        # ``git remote get-url`` adds a trailing newline; the parser
        # strips it so the caller doesn't have to.
        self.assertEqual(
            _parse_github_remote_url(
                "  https://github.com/foo/bar.git\n"
            ),
            "foo/bar",
        )


if __name__ == "__main__":
    unittest.main()
