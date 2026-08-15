from io import BytesIO

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import PcapReader, PcapWriter

from raw2pcap.generate import generate_pcap
from raw2pcap.selfcheck import SelfCheckError, verify_pcap
from raw2pcap.synth import DEFAULT_CLIENT_IP, DEFAULT_SERVER_IP

REQUEST = "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld"


def _read(pcap: bytes):
    return list(PcapReader(BytesIO(pcap)))


def _rewrite(packets) -> bytes:
    buf = BytesIO()
    writer = PcapWriter(buf, sync=True)
    for pkt in packets:
        writer.write(pkt)
    writer.flush()
    return buf.getvalue()


def _verify(pcap: bytes, server_payload: bytes | None = None) -> None:
    verify_pcap(
        pcap,
        client_ip=DEFAULT_CLIENT_IP,
        server_ip=DEFAULT_SERVER_IP,
        client_port=50000,
        server_port=80,
        client_payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        server_payload=server_payload,
    )


def test_generated_pcap_passes_selfcheck():
    # generate_pcap runs verify_pcap internally; reaching this line means it passed.
    pcap = generate_pcap(raw_request=REQUEST, raw_response=RESPONSE)
    assert pcap[:4] == b"\xd4\xc3\xb2\xa1"


def test_generated_pcap_response_only_passes():
    generate_pcap(raw_request="", raw_response=RESPONSE)


def test_bad_checksum_detected():
    pcap = generate_pcap(raw_request=REQUEST, raw_response=RESPONSE)
    packets = _read(pcap)
    victim = next(p for p in packets if p.haslayer(Raw))
    # Corrupt a payload byte but keep the stale checksums.
    load = bytearray(victim[Raw].load)
    load[0] ^= 0xFF
    victim[Raw].load = bytes(load)
    tampered = _rewrite(packets)
    with pytest.raises(SelfCheckError, match="bad checksum"):
        verify_pcap(
            tampered,
            client_ip=DEFAULT_CLIENT_IP,
            server_ip=DEFAULT_SERVER_IP,
            client_port=50000,
            server_port=80,
            client_payload=b"",
            server_payload=b"",
        )


def test_seq_gap_detected():
    pcap = generate_pcap(raw_request=REQUEST, raw_response=RESPONSE)
    packets = _read(pcap)
    victim = next(p for p in packets if p.haslayer(Raw))
    victim[TCP].seq += 5
    # Fix checksums so only the seq jump is left to be caught.
    del victim[IP].chksum, victim[TCP].chksum
    tampered = _rewrite(packets)
    with pytest.raises(SelfCheckError, match="gap, overlap or retransmission"):
        _verify(tampered)


def test_payload_mismatch_detected():
    pcap = generate_pcap(raw_request=REQUEST, raw_response=RESPONSE)
    packets = _read(pcap)
    victim = next(p for p in packets if p.haslayer(Raw))
    load = bytearray(victim[Raw].load)
    load[0] ^= 0xFF
    victim[Raw].load = bytes(load)
    del victim[IP].chksum, victim[TCP].chksum  # checksums recomputed on write
    tampered = _rewrite(packets)
    with pytest.raises(SelfCheckError, match="payload mismatch"):
        _verify(tampered)


def test_truncated_pcap_detected():
    pcap = generate_pcap(raw_request=REQUEST, raw_response=RESPONSE)
    with pytest.raises(SelfCheckError):
        verify_pcap(
            pcap[: len(pcap) // 2],
            client_ip=DEFAULT_CLIENT_IP,
            server_ip=DEFAULT_SERVER_IP,
            client_port=50000,
            server_port=80,
            client_payload=b"",
            server_payload=b"",
        )
