"""Unit tests for doctor's pure validators.

Covers the bits of ``agentbox.doctor`` that don't shell out or read
files -- the FROM-line parser and the ``Dockerfile.agentbox`` verdict
classifier. Section runners and subprocess helpers (``docker version``,
``gh api user``) are exercised by running ``agentbox doctor`` directly,
not unit-tested here.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox.doctor import (
    DockerfileFromVerdict,
    classify_dockerfile_from,
    find_first_from,
)


class FindFirstFromTests(unittest.TestCase):
    """Coverage for :func:`find_first_from`."""

    def test_simple_from(self) -> None:
        self.assertEqual(
            find_first_from("FROM agentbox-base:0.1\nRUN echo hi\n"),
            "agentbox-base:0.1",
        )

    def test_from_with_alias_returns_image(self) -> None:
        # `FROM foo AS bar` -- we capture just the image, not the alias.
        self.assertEqual(
            find_first_from("FROM node:24 AS builder\n"), "node:24"
        )

    def test_from_with_platform_flag(self) -> None:
        # The --platform flag must not be captured as the image.
        self.assertEqual(
            find_first_from("FROM --platform=linux/amd64 agentbox-base:0.1\n"),
            "agentbox-base:0.1",
        )

    def test_first_from_wins_in_multistage(self) -> None:
        # Multi-stage Dockerfile -- only the FIRST FROM matters for
        # the agentbox-base contract.
        text = "FROM agentbox-base:0.1\nRUN x\nFROM scratch\nCOPY --from=0 / /\n"
        self.assertEqual(find_first_from(text), "agentbox-base:0.1")

    def test_skips_comments_and_blanks(self) -> None:
        text = (
            "# Header comment\n"
            "\n"
            "# Another comment\n"
            "FROM agentbox-base:0.1\n"
        )
        self.assertEqual(find_first_from(text), "agentbox-base:0.1")

    def test_arg_before_from_does_not_match(self) -> None:
        # ARG directives don't have FROM in them, so the regex
        # naturally skips past them and finds the real FROM.
        text = "ARG VERSION=0.1\nFROM agentbox-base:${VERSION}\n"
        self.assertEqual(
            find_first_from(text), "agentbox-base:${VERSION}"
        )

    def test_lowercase_from_keyword(self) -> None:
        # Docker accepts `from` lowercase; we honor that.
        self.assertEqual(
            find_first_from("from agentbox-base:0.1\n"),
            "agentbox-base:0.1",
        )

    def test_no_from_returns_none(self) -> None:
        self.assertIsNone(find_first_from("RUN echo hi\nCOPY . .\n"))

    def test_empty_string_returns_none(self) -> None:
        self.assertIsNone(find_first_from(""))


class ClassifyDockerfileFromTests(unittest.TestCase):
    """Coverage for :func:`classify_dockerfile_from`."""

    def test_correct_base_version_is_ok(self) -> None:
        result = classify_dockerfile_from(
            "FROM agentbox-base:0.1\n", expected_version="0.1"
        )
        self.assertEqual(
            result, DockerfileFromVerdict("ok", detail="0.1")
        )

    def test_other_base_version_is_mismatch(self) -> None:
        result = classify_dockerfile_from(
            "FROM agentbox-base:0.2\n", expected_version="0.1"
        )
        self.assertEqual(
            result, DockerfileFromVerdict("version-mismatch", detail="0.2")
        )

    def test_non_agentbox_base_is_non_base(self) -> None:
        result = classify_dockerfile_from(
            "FROM ubuntu:24.04\n", expected_version="0.1"
        )
        self.assertEqual(
            result, DockerfileFromVerdict("non-base", detail="ubuntu:24.04")
        )

    def test_no_from_directive_is_missing(self) -> None:
        result = classify_dockerfile_from(
            "RUN echo hi\n", expected_version="0.1"
        )
        self.assertEqual(result, DockerfileFromVerdict("missing"))

    def test_empty_dockerfile_is_missing(self) -> None:
        result = classify_dockerfile_from("", expected_version="0.1")
        self.assertEqual(result, DockerfileFromVerdict("missing"))

    def test_agentbox_base_with_platform_flag(self) -> None:
        # The --platform flag must not derail the classification.
        result = classify_dockerfile_from(
            "FROM --platform=linux/amd64 agentbox-base:0.1\n",
            expected_version="0.1",
        )
        self.assertEqual(result.kind, "ok")

    def test_multistage_first_from_wins(self) -> None:
        # If the first stage isn't agentbox-base, that's a non-base
        # build -- even if a later stage references agentbox-base.
        text = (
            "FROM golang:1.26 AS builder\n"
            "RUN go build\n"
            "FROM agentbox-base:0.1\n"
            "COPY --from=builder /out /\n"
        )
        result = classify_dockerfile_from(text, expected_version="0.1")
        self.assertEqual(result.kind, "non-base")
        self.assertEqual(result.detail, "golang:1.26")


if __name__ == "__main__":
    unittest.main()
