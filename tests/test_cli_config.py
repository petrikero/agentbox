"""Unit tests for ``agentbox.cli._merge_config_file``.

Covers:
- Absent config (default location, no file) is a silent no-op.
- ``--config`` pointing at a missing file is a hard error.
- A well-formed file's ``github.repos`` is folded into ``args.repo``.
- CLI ``--repo`` flags are *additive* over the file (file first,
  CLI appended).
- Unknown top-level keys are silently kept aside for future schema
  growth (no error, no effect on args).
- All malformed shapes (non-mapping top level, non-mapping ``github:``,
  non-list ``github.repos``, non-string repo entries, broken YAML)
  produce a clean ``SystemExit`` with a useful message.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox.cli import _merge_config_file


def _ns(
    repo: list[str] | None = None,
    config: str | None = None,
    network: str | None = None,
    workdir: str | None = None,
    github_mode: str | None = None,
) -> argparse.Namespace:
    """Minimal argparse Namespace with the fields the loader reads."""
    return argparse.Namespace(
        repo=list(repo or []), config=config, network=network,
        workdir=workdir, github_mode=github_mode,
    )


class MergeConfigFileTests(unittest.TestCase):
    """Coverage for :func:`_merge_config_file`."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agentbox-cfg-")
        self.tmpdir = Path(self._tmp.name)
        # Run each test with cwd inside the tempdir so the
        # default-location lookup (``./agentbox.config.yaml``) is
        # isolated. Restore cwd afterwards.
        self._prev_cwd = Path.cwd()
        os.chdir(self.tmpdir)

    def tearDown(self) -> None:
        os.chdir(self._prev_cwd)
        self._tmp.cleanup()

    def _write_config(self, body: str, name: str = "agentbox.config.yaml") -> Path:
        path = self.tmpdir / name
        path.write_text(body, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Absence / discovery
    # ------------------------------------------------------------------

    def test_absent_default_file_is_silent_noop(self) -> None:
        ns = _ns(repo=["cli/repo"])
        result = _merge_config_file(ns)
        self.assertIsNone(result)
        self.assertEqual(ns.repo, ["cli/repo"])  # unchanged

    def test_explicit_missing_path_is_hard_error(self) -> None:
        ns = _ns(config=str(self.tmpdir / "nonexistent.yaml"))
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("config file not found", str(cm.exception))

    # ------------------------------------------------------------------
    # Happy path
    # ------------------------------------------------------------------

    def test_default_location_loads_repos(self) -> None:
        self._write_config(
            "github:\n"
            "  repos:\n"
            "    - my-org/repo-one\n"
            "    - my-org/repo-two\n"
        )
        ns = _ns()
        result = _merge_config_file(ns)
        self.assertIsNotNone(result)
        self.assertEqual(ns.repo, ["my-org/repo-one", "my-org/repo-two"])

    def test_explicit_path_loads_repos(self) -> None:
        path = self._write_config(
            "github:\n  repos:\n    - my-org/repo\n",
            name="custom.yaml",
        )
        ns = _ns(config=str(path))
        result = _merge_config_file(ns)
        self.assertEqual(result, path.resolve())
        self.assertEqual(ns.repo, ["my-org/repo"])

    def test_cli_repos_are_additive_over_file(self) -> None:
        # File first, CLI appended -- so a user running
        # `agentbox --repo extra/one` on top of a config with
        # [a/b, a/c] sees [a/b, a/c, extra/one].
        self._write_config(
            "github:\n"
            "  repos:\n"
            "    - a/b\n"
            "    - a/c\n"
        )
        ns = _ns(repo=["extra/one", "extra/two"])
        _merge_config_file(ns)
        self.assertEqual(
            ns.repo, ["a/b", "a/c", "extra/one", "extra/two"]
        )

    def test_empty_file_is_no_op(self) -> None:
        # `yaml.safe_load("")` returns None; loader treats as {}.
        self._write_config("")
        ns = _ns(repo=["cli/repo"])
        _merge_config_file(ns)
        self.assertEqual(ns.repo, ["cli/repo"])

    def test_github_block_without_repos_is_no_op(self) -> None:
        self._write_config("github: {}\n")
        ns = _ns(repo=["cli/repo"])
        _merge_config_file(ns)
        self.assertEqual(ns.repo, ["cli/repo"])

    def test_unknown_top_level_keys_are_silently_ignored(self) -> None:
        # Forward-compat: a config from a newer agentbox (with sections
        # we haven't shipped yet) must still load on an older one.
        self._write_config(
            "github:\n  repos: [a/b]\n"
            "future_section:\n  deeply:\n    nested: true\n"
        )
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(ns.repo, ["a/b"])

    # ------------------------------------------------------------------
    # Malformed shapes
    # ------------------------------------------------------------------

    def test_broken_yaml_errors_cleanly(self) -> None:
        self._write_config("github: [unclosed")
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("invalid YAML", str(cm.exception))

    def test_non_mapping_top_level_errors(self) -> None:
        self._write_config("- just\n- a\n- list\n")
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("YAML mapping", str(cm.exception))

    def test_non_mapping_github_block_errors(self) -> None:
        self._write_config("github: not-a-mapping\n")
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("'github:' must be a mapping", str(cm.exception))

    def test_non_list_repos_errors(self) -> None:
        self._write_config("github:\n  repos: my-org/repo\n")
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("'github.repos:' must be a list", str(cm.exception))

    def test_non_string_repo_entry_errors(self) -> None:
        # Repos entries must be strings or mappings; an integer is
        # neither so the loader rejects the file at parse time.
        self._write_config(
            "github:\n  repos:\n    - my-org/ok\n    - 42\n"
        )
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn(
            "entries must be strings or mappings", str(cm.exception),
        )

    # ------------------------------------------------------------------
    # Dict-form repos (per-repo policy)
    # ------------------------------------------------------------------

    def test_dict_form_repo_parses(self) -> None:
        self._write_config(
            "github:\n"
            "  repos:\n"
            "    - name: my-org/repo\n"
            "      issues: [comment, create]\n"
            "      pull_requests: [comment, review]\n"
            "      branches:\n"
            "        push: [\"agent/*\"]\n"
            "        create: [\"agent/*\"]\n"
        )
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(len(ns.repo), 1)
        entry = ns.repo[0]
        self.assertIsInstance(entry, dict)
        self.assertEqual(entry["name"], "my-org/repo")
        self.assertEqual(entry["issues"], ["comment", "create"])

    def test_mixed_str_and_dict_repos_merge_with_cli(self) -> None:
        self._write_config(
            "github:\n"
            "  repos:\n"
            "    - my-org/short\n"
            "    - name: my-org/full\n"
            "      issues: [comment]\n"
        )
        ns = _ns(repo=["cli/extra"])
        _merge_config_file(ns)
        self.assertEqual(len(ns.repo), 3)
        self.assertEqual(ns.repo[0], "my-org/short")
        self.assertIsInstance(ns.repo[1], dict)
        self.assertEqual(ns.repo[1]["name"], "my-org/full")
        self.assertEqual(ns.repo[2], "cli/extra")

    def test_dict_repo_missing_name_errors(self) -> None:
        self._write_config(
            "github:\n  repos:\n    - issues: [comment]\n"
        )
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn(
            "missing required string field 'name'", str(cm.exception),
        )

    def test_dict_repo_non_list_issues_errors(self) -> None:
        self._write_config(
            "github:\n"
            "  repos:\n"
            "    - name: my-org/repo\n"
            "      issues: comment\n"
        )
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("'github.repos[].issues'", str(cm.exception))

    def test_dict_repo_branches_not_mapping_errors(self) -> None:
        self._write_config(
            "github:\n"
            "  repos:\n"
            "    - name: my-org/repo\n"
            "      branches: agent/*\n"
        )
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn(
            "'github.repos[].branches' must be a mapping",
            str(cm.exception),
        )

    def test_dict_repo_branches_push_non_list_errors(self) -> None:
        self._write_config(
            "github:\n"
            "  repos:\n"
            "    - name: my-org/repo\n"
            "      branches:\n"
            "        push: agent/main\n"
        )
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn(
            "'github.repos[].branches.push'", str(cm.exception),
        )

    # ------------------------------------------------------------------
    # github.mode key
    # ------------------------------------------------------------------

    def test_github_mode_loads_when_cli_absent(self) -> None:
        self._write_config("github:\n  mode: scoped\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(ns.github_mode, "scoped")

    def test_github_mode_cli_overrides_config(self) -> None:
        self._write_config("github:\n  mode: scoped\n")
        ns = _ns(github_mode="unrestricted")
        _merge_config_file(ns)
        self.assertEqual(ns.github_mode, "unrestricted")

    def test_github_mode_invalid_value_errors(self) -> None:
        self._write_config("github:\n  mode: chaos\n")
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("unknown 'github.mode:' value", str(cm.exception))

    def test_github_mode_auto_round_trips(self) -> None:
        self._write_config("github:\n  mode: auto\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(ns.github_mode, "auto")

    # ------------------------------------------------------------------
    # Network mode key
    # ------------------------------------------------------------------

    def test_network_absent_leaves_args_network_none(self) -> None:
        # No `network:` key in file -> args.network stays whatever the
        # caller set it to (None when no CLI flag).
        self._write_config("github:\n  repos: [a/b]\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertIsNone(ns.network)

    def test_network_from_config_loads_when_cli_absent(self) -> None:
        self._write_config("network: transparent-shared\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(ns.network, "transparent-shared")

    def test_network_cli_overrides_config(self) -> None:
        self._write_config("network: transparent-shared\n")
        ns = _ns(network="permissive")
        _merge_config_file(ns)
        self.assertEqual(ns.network, "permissive")

    def test_network_invalid_value_in_config_errors(self) -> None:
        self._write_config("network: chaos-mode\n")
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("unknown 'network:' value", str(cm.exception))

    def test_network_permissive_explicit_in_config(self) -> None:
        self._write_config("network: permissive\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(ns.network, "permissive")

    def test_network_isolated_value_loads_fine_at_config_layer(self) -> None:
        # transparent-isolated is a valid YAML value; the launcher
        # bails on it later in _main, not here. This test pins that
        # behaviour so the validation point is unambiguous.
        self._write_config("network: transparent-isolated\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(ns.network, "transparent-isolated")

    # ------------------------------------------------------------------
    # Container workdir override (workdir:) key
    # ------------------------------------------------------------------

    def test_workdir_absent_leaves_args_workdir_none(self) -> None:
        self._write_config("github:\n  repos: [a/b]\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertIsNone(ns.workdir)

    def test_workdir_from_config_loads_when_cli_absent(self) -> None:
        self._write_config("workdir: /app\n")
        ns = _ns()
        _merge_config_file(ns)
        self.assertEqual(ns.workdir, "/app")

    def test_workdir_cli_overrides_config(self) -> None:
        self._write_config("workdir: /from-config\n")
        ns = _ns(workdir="/from-cli")
        _merge_config_file(ns)
        self.assertEqual(ns.workdir, "/from-cli")

    def test_workdir_non_string_errors(self) -> None:
        self._write_config("workdir:\n  - a\n  - b\n")
        ns = _ns()
        with self.assertRaises(SystemExit) as cm:
            _merge_config_file(ns)
        self.assertIn("'workdir:' must be a string", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
