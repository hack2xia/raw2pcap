"""Round-trip self-check: re-parse a synthesized pcap and verify it.

The generator builds packets in memory, so any bug there silently produces a
bad capture. This module is the post-generation gate: it re-dissects the pcap
bytes and asserts checksums are valid, sequence numbers are continuous (no
gap/overlap/retransmission), and the reassembled payloads byte-match the HTTP
messages that were supposed to be on the wire.
"""

from io import BytesIO

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw, raw
from scapy.utils import PcapReader


class SelfCheckError(RuntimeError):
    """Raised when a generated pcap fails post-generation verification."""


def _checksums_ok(pkt) -> bool:
    """Recompute IP and TCP checksums and compare with the ones on the wire."""
    ip = IP(raw(pkt[IP]))
    saved_ip, saved_tcp = ip.chksum, ip[TCP].chksum
    del ip.chksum, ip[TCP].chksum
    rebuilt = IP(bytes(ip))
    return rebuilt.chksum == saved_ip and rebuilt[TCP].chksum == saved_tcp


def verify_pcap(
    pcap: bytes,
    *,
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
    client_payload: bytes,
    server_payload: bytes | None,
) -> None:
    """Re-parse *pcap* and assert it is a faithful TCP session.

    Raises SelfCheckError on any inconsistency; returns None on success.
    """
    try:
        packets = list(PcapReader(BytesIO(pcap)))
    except Exception as exc:
        raise SelfCheckError(f"pcap is not parseable: {exc}") from exc
    if not packets:
        raise SelfCheckError("pcap contains no packets")

    # direction (src ip, src port) -> [expected next seq or None, payload bytes]
    streams: dict[tuple[str, int], list] = {
        (client_ip, client_port): [None, bytearray()],
        (server_ip, server_port): [None, bytearray()],
    }
    saw_syn = saw_fin = False
    for i, pkt in enumerate(packets):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            raise SelfCheckError(f"packet {i}: missing IP/TCP layer")
        if not _checksums_ok(pkt):
            raise SelfCheckError(f"packet {i}: bad checksum")
        ip, tcp = pkt[IP], pkt[TCP]
        key = (ip.src, tcp.sport)
        if key not in streams:
            raise SelfCheckError(f"packet {i}: unexpected endpoint {ip.src}:{tcp.sport}")
        expected, buf = streams[key]
        if expected is not None and tcp.seq != expected:
            raise SelfCheckError(
                f"packet {i}: seq {tcp.seq} != expected {expected} (gap, overlap or retransmission)"
            )
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        buf += payload
        advance = len(payload) + (1 if tcp.flags.S or tcp.flags.F else 0)
        streams[key][0] = tcp.seq + advance
        saw_syn = saw_syn or bool(tcp.flags.S and not tcp.flags.A)
        saw_fin = saw_fin or bool(tcp.flags.F)

    if not saw_syn or not saw_fin:
        raise SelfCheckError("pcap lacks a complete TCP session (SYN/FIN missing)")

    client_got = bytes(streams[(client_ip, client_port)][1])
    if client_got != client_payload:
        raise SelfCheckError(
            f"client payload mismatch: reassembled {len(client_got)} bytes, "
            f"expected {len(client_payload)}"
        )
    server_got = bytes(streams[(server_ip, server_port)][1])
    expected_server = server_payload or b""
    if server_got != expected_server:
        raise SelfCheckError(
            f"server payload mismatch: reassembled {len(server_got)} bytes, "
            f"expected {len(expected_server)}"
        )
