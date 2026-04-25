# agentbox proxy sidecar image. Used only by `network: transparent-shared`.
#
# Built with `src/agentbox` as the build context (so the Dockerfile
# can COPY the agentbox.proxy package into the image without the
# context climbing out of the package tree). The launcher invokes
# this with `-f src/agentbox/sandbox/proxy/Dockerfile src/agentbox`.
#
# The sidecar runs in its own container that the agent container shares
# a network namespace with via `--network container:<sidecar>`. The
# entrypoint installs iptables NAT rules to redirect the agent's
# TCP/80 + TCP/443 traffic to mitmproxy's transparent listener,
# spawns a UDP/53 DNS sinkhole, and exec-s mitmdump under a
# dedicated low-privilege UID so the iptables --uid-owner exemption
# can pick it out and let its upstream traffic skip the redirect.

FROM python:3.14-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iptables ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Dedicated UID 4242 for mitmproxy. Matches the --uid-owner used by
# the entrypoint's iptables RETURN rule (so mitmproxy's own egress to
# upstream isn't caught by the REDIRECT rule) and the os.setuid drop
# at the end of the entrypoint's privileged setup. UID is hard-coded
# rather than looked up at runtime so the iptables rule and the
# privilege drop agree without a passwd-reading roundtrip.
RUN useradd --system --uid 4242 --create-home mitmproxy

# Runtime deps for the agentbox.proxy package.
RUN pip install --no-cache-dir 'mitmproxy>=11' 'pyyaml>=6' 'graphql-core>=3.2'

# Stage the agentbox.proxy package so `python -m agentbox.proxy` works.
# We only need the package marker + the proxy/ subpackage; cli.py /
# progress/ etc. are launcher-side and never run in the sidecar.
COPY __init__.py /opt/agentbox/agentbox/__init__.py
COPY proxy /opt/agentbox/agentbox/proxy
ENV PYTHONPATH=/opt/agentbox

# Sidecar-only assets.
COPY sandbox/proxy/entrypoint.py /usr/local/bin/proxy-entrypoint
COPY sandbox/proxy/dns.py /opt/agentbox/dns.py

ENTRYPOINT ["python", "/usr/local/bin/proxy-entrypoint"]
