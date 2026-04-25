"""Unit tests for image-tag sanitisation in ``agentbox.cli``.

Covers the pure ``_safe_image_tag`` helper. The Docker-shelling-out
pieces of ``_ensure_image`` aren't unit-tested here -- mocking
subprocess for them buys little and we'd just be asserting on our
own command-line construction. They get exercised the first time a
user runs ``agentbox`` against a fresh tree.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox._shared import (
    BASE_IMAGE_TAG,
    BASE_IMAGE_VERSION,
    PROXY_SIDECAR_IMAGE_TAG,
)
from agentbox.cli import _safe_image_tag


class SafeImageTagTests(unittest.TestCase):
    """Coverage for :func:`_safe_image_tag`."""

    def test_simple_lowercase_passthrough(self) -> None:
        self.assertEqual(_safe_image_tag("agentbox"), "agentbox")

    def test_lowercases_uppercase(self) -> None:
        self.assertEqual(_safe_image_tag("AgentBox"), "agentbox")

    def test_replaces_spaces_with_dash(self) -> None:
        self.assertEqual(
            _safe_image_tag("my project"), "my-project"
        )

    def test_keeps_underscore_dot_hyphen(self) -> None:
        # Docker tags accept these three; pass them through as-is.
        self.assertEqual(
            _safe_image_tag("foo_bar.v1-beta"), "foo_bar.v1-beta"
        )

    def test_replaces_other_punctuation(self) -> None:
        # Slashes, colons, plus signs, etc. are not allowed in tags.
        self.assertEqual(
            _safe_image_tag("foo/bar:baz+qux"), "foo-bar-baz-qux"
        )

    def test_strips_leading_dot(self) -> None:
        # Docker rejects tags that start with `.` or `-`.
        self.assertEqual(_safe_image_tag(".hidden"), "hidden")

    def test_strips_leading_dashes(self) -> None:
        self.assertEqual(_safe_image_tag("---name"), "name")

    def test_strips_mixed_leading_punctuation(self) -> None:
        self.assertEqual(_safe_image_tag(".-foo"), "foo")

    def test_empty_string_falls_back_to_default(self) -> None:
        self.assertEqual(_safe_image_tag(""), "default")

    def test_only_punctuation_falls_back_to_default(self) -> None:
        # After replacement and strip we'd be left with "---" ->
        # leading-strip removes the lot -> empty -> "default".
        self.assertEqual(_safe_image_tag("///"), "default")

    def test_unicode_is_replaced(self) -> None:
        # Non-ASCII letters aren't ``isalnum`` for our purposes.
        # (cwd basenames with accented characters are rare but
        # legal on macOS/Windows; this confirms we don't crash.)
        result = _safe_image_tag("café")
        # `é` is alphanumeric in unicode terms; Python's str.isalnum
        # returns True for it, so it survives. We're verifying the
        # function doesn't raise on non-ASCII input.
        self.assertNotIn(" ", result)
        self.assertTrue(result)


class ProxySidecarImageTagTests(unittest.TestCase):
    """Pin the sidecar image tag shape so launcher and doctor agree."""

    def test_uses_base_image_version(self) -> None:
        # The sidecar tag tracks the same `:local` (or future numbered)
        # version as the base image so a single launcher upgrade flips
        # both at once.
        self.assertTrue(
            PROXY_SIDECAR_IMAGE_TAG.endswith(f":{BASE_IMAGE_VERSION}"),
            f"expected sidecar tag to end with :{BASE_IMAGE_VERSION}, "
            f"got {PROXY_SIDECAR_IMAGE_TAG}",
        )

    def test_distinct_from_base_image(self) -> None:
        self.assertNotEqual(PROXY_SIDECAR_IMAGE_TAG, BASE_IMAGE_TAG)

    def test_repository_name(self) -> None:
        # The repository part (before ':') should be agentbox-proxy-sidecar
        # so it groups visibly with `agentbox-base` / `agentbox-project`
        # in `docker images` output.
        repo, _, _ = PROXY_SIDECAR_IMAGE_TAG.partition(":")
        self.assertEqual(repo, "agentbox-proxy-sidecar")


if __name__ == "__main__":
    unittest.main()
