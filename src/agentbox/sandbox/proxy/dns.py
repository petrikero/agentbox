"""DNS sinkhole for the agentbox proxy sidecar.

Listens on UDP/5353 (a non-privileged port). The sidecar's iptables
NAT rules redirect UDP/53 traffic to this listener, so the agent's
``getaddrinfo`` requests land here transparently. Binding 5353
instead of 53 avoids needing ``CAP_NET_BIND_SERVICE`` and lets the
sinkhole run as the unprivileged ``mitmproxy`` user.

Answers every A query with the netns's own IPv4 -- so the agent's
TCP connect lands at the same netns, where mitmproxy in transparent
mode reads the original destination via ``SO_ORIGINAL_DST`` (set
by the iptables NAT REDIRECT rule on TCP/80+443) and recovers what
the agent thought it was talking to.

NXDOMAIN for AAAA: forces IPv4. Our iptables rules only match v4
traffic; a v6 path would otherwise be an unintercepted egress hole.

Not a real DNS server -- no caching, no upstream forwarding. The
point is that nothing leaks out of the netns over UDP/53 that an
attacker could use to exfiltrate data via DNS query labels.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import sys


def _local_ipv4() -> bytes:
    """Best-effort: pick the netns's outbound IPv4 address.

    Connects a UDP socket to a public IP without sending anything;
    the local address the kernel chose is what we want. Falls back to
    127.0.0.1 if no route exists (which still works -- iptables NAT
    redirect catches the loopback packet).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return socket.inet_aton(s.getsockname()[0])
    except OSError:
        return socket.inet_aton("127.0.0.1")
    finally:
        s.close()


_LOCAL_IP = _local_ipv4()


def _build_response(query: bytes, local_ip: bytes) -> bytes:
    """Return a DNS response: A -> local_ip, AAAA -> NXDOMAIN, else FORMERR."""
    if len(query) < 12:
        return b""
    txn_id = query[:2]
    try:
        _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
            ">HHHHH", query[2:12]
        )
    except struct.error:
        return b""
    if qdcount != 1:
        return b""

    # Walk the question name.
    pos = 12
    while pos < len(query) and query[pos] != 0:
        if query[pos] & 0xC0:  # compression pointer (not legal in queries)
            return b""
        pos += query[pos] + 1
        if pos >= len(query):
            return b""
    name_end = pos + 1  # skip the terminator
    if name_end + 4 > len(query):
        return b""
    qtype, _qclass = struct.unpack(">HH", query[name_end:name_end + 4])
    question = query[12:name_end + 4]

    if qtype == 1:  # A
        rdata = local_ip
        answer = (
            b"\xc0\x0c"  # name pointer back to question
            + struct.pack(">HHIH", 1, 1, 60, 4)  # TYPE A, CLASS IN, TTL 60, RDLENGTH 4
            + rdata
        )
        flags_resp = 0x8180  # standard response, recursion-available, NOERROR
        ancount = 1
    else:
        # AAAA, MX, TXT, ...: NXDOMAIN. Keeps DNS exfil channels closed
        # and steers the resolver back to A.
        answer = b""
        flags_resp = 0x8183  # standard response + NXDOMAIN
        ancount = 0

    header = txn_id + struct.pack(
        ">HHHHH", flags_resp, qdcount, ancount, 0, 0
    )
    return header + question + answer


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # type: ignore[override]
        data, sock = self.request
        resp = _build_response(data, _LOCAL_IP)
        if resp:
            sock.sendto(resp, self.client_address)


class _UDPServer(socketserver.UDPServer):
    allow_reuse_address = True


def main() -> None:
    # Non-privileged port; iptables redirects UDP/53 here.
    addr = ("0.0.0.0", 5353)
    print(
        f"agentbox-dns: listening on {addr[0]}:{addr[1]}; "
        f"A -> {socket.inet_ntoa(_LOCAL_IP)}, others -> NXDOMAIN",
        file=sys.stderr, flush=True,
    )
    with _UDPServer(addr, _Handler) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
