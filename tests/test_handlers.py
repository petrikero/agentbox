"""Unit tests for credential handlers.

Covers:
- ``_try_swap`` helper (Bearer, ``token``, Basic-Auth Base64, no-match).
- ``GithubCredentialHandler``:
  - ``matches_host`` for in-scope and out-of-scope hosts.
  - Bearer + Basic-Auth swap on a scoped host.
  - Foreign-credential stripping by default; preserved with
    ``allow_foreign=True``.
  - Unrelated headers untouched.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

# Prefer the in-tree source over any cached install in site-packages.
_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from mitmproxy.http import Request

from agentbox.proxy import handlers as handlers_mod
from agentbox.proxy.handlers import (
    GithubCredentialHandler,
    _try_swap,
)


def _make_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
) -> Request:
    return Request.make(method, url, b"", cast(Any, headers or {}))


class TrySwapTests(unittest.TestCase):
    """Coverage for the pure ``_try_swap`` helper."""

    def test_bearer_swap(self) -> None:
        self.assertEqual(
            _try_swap("Bearer ghp_FAKE", "ghp_FAKE", "ghp_REAL"),
            "Bearer ghp_REAL",
        )

    def test_token_prefix_swap(self) -> None:
        # gh CLI legacy form: `Authorization: token <PAT>`.
        self.assertEqual(
            _try_swap("token ghp_FAKE", "ghp_FAKE", "ghp_REAL"),
            "token ghp_REAL",
        )

    def test_basic_auth_swap_round_trip(self) -> None:
        original = base64.b64encode(b"x-access-token:ghp_FAKE").decode()
        swapped = _try_swap(f"Basic {original}", "ghp_FAKE", "ghp_REAL")
        assert swapped is not None
        new_b64 = swapped.removeprefix("Basic ")
        self.assertEqual(
            base64.b64decode(new_b64).decode(), "x-access-token:ghp_REAL"
        )

    def test_no_match_returns_none(self) -> None:
        self.assertIsNone(_try_swap("Bearer ghp_OTHER", "ghp_FAKE", "ghp_REAL"))

    def test_basic_with_invalid_base64_returns_none(self) -> None:
        self.assertIsNone(_try_swap("Basic !!!notbase64!!!", "ghp_FAKE", "ghp_REAL"))

    def test_no_basic_no_surrogate_returns_none(self) -> None:
        self.assertIsNone(_try_swap("Token foo", "ghp_FAKE", "ghp_REAL"))

    def test_basic_scheme_case_insensitive(self) -> None:
        # RFC 7235 says auth schemes are case-insensitive. We must
        # still rewrite the payload regardless of the casing the
        # client used, and preserve that exact casing on output so
        # downstream services see the same scheme they would have.
        cred = base64.b64encode(b"x-access-token:ghp_FAKE").decode()
        for scheme in ("basic", "BASIC", "BaSiC"):
            swapped = _try_swap(
                f"{scheme} {cred}", "ghp_FAKE", "ghp_REAL"
            )
            assert swapped is not None, scheme
            self.assertTrue(swapped.startswith(f"{scheme} "), scheme)
            new_b64 = swapped[len(scheme) + 1:]
            self.assertEqual(
                base64.b64decode(new_b64).decode(),
                "x-access-token:ghp_REAL",
                scheme,
            )

    def test_basic_tolerates_extra_whitespace(self) -> None:
        # Some clients send a tab, multiple spaces, or leading
        # whitespace before the scheme; RFC 7235 allows it. Make
        # sure the swap still happens.
        cred = base64.b64encode(b"x-access-token:ghp_FAKE").decode()
        for raw in (
            f"Basic\t{cred}",        # tab between scheme and payload
            f"Basic   {cred}",       # multiple spaces
            f"  Basic {cred}",       # leading whitespace
        ):
            swapped = _try_swap(raw, "ghp_FAKE", "ghp_REAL")
            assert swapped is not None, raw
            self.assertTrue(swapped.startswith("Basic "), raw)
            new_b64 = swapped.removeprefix("Basic ")
            self.assertEqual(
                base64.b64decode(new_b64).decode(),
                "x-access-token:ghp_REAL",
                raw,
            )


class GithubHandlerTests(unittest.TestCase):
    """Coverage for ``GithubCredentialHandler`` scoping + swap policy."""

    def setUp(self) -> None:
        # Silence ctx.log so tests don't fail outside a mitmproxy run.
        self._patch = patch.object(
            handlers_mod, "ctx",
            SimpleNamespace(log=SimpleNamespace(warn=lambda *a, **k: None,
                                                info=lambda *a, **k: None)),
        )
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()

    def _handler(self, *, allow_foreign: bool = False) -> GithubCredentialHandler:
        return GithubCredentialHandler(
            surrogate="ghp_FAKE",
            real="ghp_REAL",
            allow_foreign=allow_foreign,
        )

    def test_matches_known_github_hosts(self) -> None:
        h = self._handler()
        for host in (
            "api.github.com",
            "github.com",
            "API.GitHub.COM",
            "raw.github.com",
            "codeload.github.com",
            "objects.githubusercontent.com",
            "npm.pkg.github.com",
        ):
            self.assertTrue(h.matches_host(host), host)

    def test_does_not_match_unrelated_hosts(self) -> None:
        h = self._handler()
        for host in (
            "api.anthropic.com",
            "registry.npmjs.org",
            "pypi.org",
            "evil.example.com",
        ):
            self.assertFalse(h.matches_host(host), host)

    def test_bearer_swapped(self) -> None:
        h = self._handler()
        req = _make_request(
            "GET", "https://api.github.com/repos/x/y",
            headers={"Authorization": "Bearer ghp_FAKE"},
        )
        h.handle(req)
        self.assertEqual(req.headers["Authorization"], "Bearer ghp_REAL")

    def test_basic_auth_swap_for_git_push(self) -> None:
        # gh auth git-credential sends `x-access-token:<token>` Basic auth.
        h = self._handler()
        cred = base64.b64encode(b"x-access-token:ghp_FAKE").decode()
        req = _make_request(
            "POST",
            "https://github.com/myorg/myrepo.git/git-receive-pack",
            headers={"Authorization": f"Basic {cred}"},
        )
        h.handle(req)
        new_b64 = req.headers["Authorization"].removeprefix("Basic ")
        self.assertEqual(
            base64.b64decode(new_b64).decode(), "x-access-token:ghp_REAL"
        )

    def test_foreign_credential_dropped_by_default(self) -> None:
        h = self._handler()
        req = _make_request(
            "GET", "https://api.github.com/repos/x/y",
            headers={"Authorization": "Bearer ghp_ATTACKER_TOKEN"},
        )
        h.handle(req)
        self.assertNotIn("Authorization", req.headers)

    def test_foreign_credential_preserved_when_allow_foreign(self) -> None:
        h = self._handler(allow_foreign=True)
        req = _make_request(
            "GET", "https://api.github.com/repos/x/y",
            headers={"Authorization": "Bearer ghp_ATTACKER_TOKEN"},
        )
        h.handle(req)
        self.assertEqual(
            req.headers["Authorization"], "Bearer ghp_ATTACKER_TOKEN"
        )

    def test_unrelated_header_left_alone(self) -> None:
        h = self._handler()
        req = _make_request(
            "GET", "https://api.github.com/x",
            headers={
                "Authorization": "Bearer ghp_FAKE",
                "X-Custom-Token": "Bearer ghp_FAKE",
            },
        )
        h.handle(req)
        self.assertEqual(req.headers["Authorization"], "Bearer ghp_REAL")
        self.assertEqual(req.headers["X-Custom-Token"], "Bearer ghp_FAKE")


if __name__ == "__main__":
    unittest.main()
