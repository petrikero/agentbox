"""Entry point: ``python -m agentbox.proxy``.

Wraps mitmdump with the agentbox filter addon. Exists so the launcher can
spawn a self-contained subprocess without callers needing to know mitmproxy
CLI conventions.

Two modes:

- **regular** (default): explicit-proxy CONNECT mode, listens on
  ``--listen-host:--port``. The launcher uses this for
  ``network: permissive`` -- the container reaches it via
  ``HTTPS_PROXY=http://host.docker.internal:<port>``.
- **transparent**: mitmproxy's transparent mode, single combined
  port. The sidecar entrypoint uses this for
  ``network: transparent-shared`` -- the container's traffic is
  redirected here by iptables NAT rules in the shared netns, and
  mitmproxy reads the original destination via ``SO_ORIGINAL_DST``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mitmproxy.tools.main import mitmdump


def main() -> None:
    parser = argparse.ArgumentParser(prog="agentbox.proxy")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--allowlist", required=True)
    parser.add_argument(
        "--github-policy", required=True,
        help="Path to JSON describing the resolved GitHub access policy: "
             "{mode, repos: [{full_name, node_id, issues, pull_requests, "
             "branches}]}. The chunk-3 enforcement layer reads the "
             "per-repo lists; chunk 2 only consumes mode + repo identity.",
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument(
        "--transparent", action="store_true",
        help="Run mitmdump in transparent mode (used by the sidecar "
             "deployment). Skips --listen-host (mitmproxy binds 0.0.0.0 "
             "in transparent mode) and uses --mode transparent so the "
             "original destination is recovered via SO_ORIGINAL_DST.",
    )
    parser.add_argument(
        "--mock-llm", default="", metavar="PATH",
        help="Path to a Python module that scripts mock LLM responses. "
             "When set, requests to api.anthropic.com / api.openai.com / "
             "api.z.ai are short-circuited with replies from this script "
             "instead of being forwarded upstream. Test affordance; "
             "leave empty for normal operation.",
    )
    parser.add_argument(
        "--mock-llm-transcript", default="", metavar="PATH",
        help="Path to append a JSONL transcript of intercepted LLM "
             "requests / responses. Only meaningful with --mock-llm.",
    )
    args = parser.parse_args()

    filter_path = Path(__file__).parent / "filter.py"

    extra_set: list[str] = []
    if args.mock_llm:
        extra_set += [
            "--set", f"agentbox_mock_llm_script={args.mock_llm}",
        ]
    if args.mock_llm_transcript:
        extra_set += [
            "--set",
            f"agentbox_mock_llm_transcript={args.mock_llm_transcript}",
        ]

    if args.transparent:
        sys.argv = [
            "mitmdump",
            "--mode", "transparent",
            "--listen-port", str(args.port),
            # --showhost makes mitmproxy log the SNI/Host-derived target
            # rather than the raw IP it sees on the redirected socket --
            # easier to read in the sidecar logs.
            "--showhost",
            "-s", str(filter_path),
            "--set", f"agentbox_credentials={args.credentials}",
            "--set", f"agentbox_allowlist={args.allowlist}",
            "--set", f"agentbox_github_policy={args.github_policy}",
            *extra_set,
        ]
    else:
        sys.argv = [
            "mitmdump",
            "--listen-host", args.listen_host,
            "--listen-port", str(args.port),
            "-s", str(filter_path),
            "--set", f"agentbox_credentials={args.credentials}",
            "--set", f"agentbox_allowlist={args.allowlist}",
            "--set", f"agentbox_github_policy={args.github_policy}",
            *extra_set,
        ]
    mitmdump()


if __name__ == "__main__":
    main()
