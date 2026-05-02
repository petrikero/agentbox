"""Per-provider credential handlers for the agentbox proxy.

Each handler owns one credential's scoping rules (which hosts it
applies to), the swap mechanics (Bearer / Basic / inline), and the
foreign-credential policy. The filter dispatches to a handler only
on requests whose host matches that handler's scope, so e.g. a
GitHub PAT swap never fires on a request to ``api.anthropic.com``.

Today there is one handler: ``GithubCredentialHandler``. New
providers (Anthropic OAuth, AWS SigV4, ...) get their own classes
here and a corresponding key in the launcher's credentials JSON.
"""

from __future__ import annotations

import base64
from fnmatch import fnmatch

from mitmproxy import ctx, http


class GithubCredentialHandler:
    """Surrogate-to-real swap for a GitHub PAT.

    Scopes cover everything the GitHub CLI/API and ``git`` over HTTPS
    touch: ``api.github.com`` (REST + GraphQL), ``github.com`` (git
    smart-HTTP), ``*.github.com`` (raw, codeload, uploads),
    ``*.githubusercontent.com``, ``*.pkg.github.com``.

    Auth shapes recognised on ``Authorization``:

    - ``Bearer ghp_...``  (REST, GraphQL, modern ``gh`` CLI)
    - ``token ghp_...``   (legacy ``gh`` CLI form)
    - ``Basic <b64(x-access-token:ghp_...)>``  (``git push``/``git fetch``
      via ``gh auth git-credential`` over HTTPS)

    Foreign-credential policy: any ``Authorization`` header on a
    scoped host that doesn't carry the surrogate is dropped, so an
    in-container attacker can't smuggle their own PAT through.
    Override only by passing ``allow_foreign=True``.

    Defense-in-depth credential scrubbing: GitHub historically
    accepted credentials on alternate channels too -- ``Cookie``
    (web-session auth), ``X-GitHub-Token`` (legacy header), and
    the deprecated-but-still-recognised ``?access_token=...``
    query parameter. agentbox never legitimately uses any of
    these, so we strip them on every scoped-host request to
    close those alternate channels.
    """

    SCOPES: tuple[str, ...] = (
        "api.github.com",
        "github.com",
        "*.github.com",
        "*.githubusercontent.com",
        "*.pkg.github.com",
    )
    HEADER_LOWER: str = "authorization"

    # Headers we always strip on a scoped-host request. None of
    # these are auth carriers we use; presence is either an
    # in-container leak attempt or a holdover from some earlier
    # tool's environment. Compared case-insensitively against the
    # request header names.
    _SCRUB_HEADERS_LOWER: tuple[str, ...] = (
        "cookie",
        "x-github-token",
    )
    # Query parameters that GitHub accepts as alternate credential
    # carriers. We always remove these on scoped hosts so an
    # attacker-supplied URL like
    # ``api.github.com/...?access_token=ghp_real`` can't smuggle
    # a foreign PAT through.
    _SCRUB_QUERY_PARAMS: tuple[str, ...] = (
        "access_token",
    )

    def __init__(
        self,
        *,
        surrogate: str,
        real: str,
        allow_foreign: bool = False,
    ) -> None:
        self.surrogate = surrogate
        self.real = real
        self.allow_foreign = allow_foreign

    def matches_host(self, host: str) -> bool:
        h = host.lower()
        return any(fnmatch(h, s) for s in self.SCOPES)

    def handle(self, request: http.Request) -> None:
        host = request.pretty_host.lower()
        for name in list(request.headers.keys()):
            if name.lower() != self.HEADER_LOWER:
                continue
            value = request.headers[name]
            swapped = _try_swap(value, self.surrogate, self.real)
            if swapped is not None:
                request.headers[name] = swapped
                continue
            if not self.allow_foreign:
                # Don't log the header value -- it may be a real token even
                # though it isn't ours.
                ctx.log.warn(
                    f"agentbox: dropped foreign credential header "
                    f"'{name}' on {host}"
                )
                del request.headers[name]
        if not self.allow_foreign:
            self._scrub_alternate_carriers(request, host)

    def _scrub_alternate_carriers(
        self, request: http.Request, host: str,
    ) -> None:
        """Remove non-Authorization credential channels.

        Cookie / X-GitHub-Token / ?access_token= are alternate
        auth carriers GitHub recognises. We never use them
        legitimately, so an in-container request that carries
        any of them is either a smuggled credential or noise
        from an earlier tool. Either way, drop on scoped hosts.
        """
        for name in list(request.headers.keys()):
            if name.lower() in self._SCRUB_HEADERS_LOWER:
                ctx.log.warn(
                    f"agentbox: dropped alternate credential header "
                    f"'{name}' on {host}"
                )
                del request.headers[name]
        # mitmproxy exposes query parameters via request.query
        # (a MultiDictView). Iterate over a list copy because
        # deletion mutates the underlying store.
        try:
            query_keys = list(request.query.keys())
        except AttributeError:
            return
        for key in query_keys:
            if key.lower() in self._SCRUB_QUERY_PARAMS:
                ctx.log.warn(
                    f"agentbox: dropped query credential carrier "
                    f"'?{key}=...' on {host}"
                )
                del request.query[key]


def _try_swap(value: str, surrogate: str, real: str) -> str | None:
    """Return ``value`` with ``surrogate`` swapped for ``real``, or ``None``.

    Recognises both inline occurrences (``Bearer ghp_...``,
    ``token ghp_...``) and Basic-Auth Base64 payloads (``git push``
    via ``gh auth git-credential``). The ``Basic`` scheme match is
    case-insensitive and tolerant of arbitrary whitespace between
    the scheme and the credentials, per RFC 7235's case-insensitive
    auth scheme rule. The client's original scheme casing is
    preserved in the rewritten header.
    """
    if surrogate in value:
        return value.replace(surrogate, real)
    parts = value.lstrip().split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "basic":
        scheme, payload = parts
        try:
            decoded = base64.b64decode(payload).decode("utf-8")
        except Exception:
            return None
        if surrogate in decoded:
            new_decoded = decoded.replace(surrogate, real)
            new_b64 = base64.b64encode(
                new_decoded.encode("utf-8")
            ).decode("ascii")
            return f"{scheme} {new_b64}"
    return None
