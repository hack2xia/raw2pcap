from io import BytesIO

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import rdpcap

from raw2pcap.generate import generate_pcap
from raw2pcap.synth import build_session

REQUEST = b"GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld"


def _read(pcap_bytes):
    return rdpcap(BytesIO(pcap_bytes))


def test_pcap_magic_and_structure():
    pcap = build_session(REQUEST, RESPONSE, base_time=1_700_000_000.0)
    assert pcap[:4] == b"\xd4\xc3\xb2\xa1"
    pkts = _read(pcap)
    # handshake(3) + req(2) + resp(2) + close(4)
    assert len(pkts) == 11


def test_handshake_flags_and_direction():
    pkts = _read(build_session(REQUEST, RESPONSE, base_time=1_700_000_000.0))
    syn, synack, ack = pkts[0], pkts[1], pkts[2]
    assert syn[TCP].flags == "S"
    assert syn[IP].src == "10.10.10.1" and syn[IP].dst == "10.10.10.2"
    assert synack[TCP].flags == "SA"
    assert synack[IP].src == "10.10.10.2"
    assert synack[TCP].ack == syn[TCP].seq + 1
    assert ack[TCP].flags == "A"
    assert ack[TCP].seq == syn[TCP].seq + 1
    assert ack[TCP].ack == synack[TCP].seq + 1


def test_payloads_and_closing():
    pkts = _read(build_session(REQUEST, RESPONSE, base_time=1_700_000_000.0))
    payloads = [bytes(p[Raw].load) for p in pkts if p.haslayer(Raw)]
    assert REQUEST in payloads
    assert RESPONSE in payloads
    fins = [p for p in pkts if p[TCP].flags.F]
    assert len(fins) == 2  # one FIN per direction


def test_seq_ack_consistency():
    pkts = _read(build_session(REQUEST, RESPONSE, base_time=1_700_000_000.0))
    # The packet carrying the request must be acked by the following server ACK.
    req_pkt = next(p for p in pkts if p.haslayer(Raw) and p[Raw].load == REQUEST)
    idx = list(pkts).index(req_pkt)
    server_ack = pkts[idx + 1]
    assert server_ack[TCP].flags == "A"
    assert server_ack[TCP].ack == req_pkt[TCP].seq + len(REQUEST)


def test_large_body_is_segmented_by_mss():
    body = b"x" * 5000
    pcap = build_session(REQUEST, RESPONSE + body, mss=1000, base_time=1_700_000_000.0)
    pkts = _read(pcap)
    resp_segments = [
        bytes(p[Raw].load) for p in pkts if p.haslayer(Raw) and p[IP].src == "10.10.10.2"
    ]
    assert b"".join(resp_segments) == RESPONSE + body
    assert max(len(s) for s in resp_segments) <= 1000


def test_checksums_are_computed():
    pkts = _read(build_session(REQUEST, RESPONSE, base_time=1_700_000_000.0))
    for pkt in pkts:
        assert pkt[IP].chksum is not None
        assert pkt[TCP].chksum is not None
        # Recompute from scratch and compare with what was written.
        rebuilt = IP(bytes(pkt[IP]))
        assert rebuilt.chksum == pkt[IP].chksum
        assert rebuilt[TCP].chksum == pkt[TCP].chksum


def test_timestamps_increase():
    pkts = _read(build_session(REQUEST, RESPONSE, base_time=1_700_000_000.0))
    times = [float(p.time) for p in pkts]
    assert times == sorted(times)
    assert times[0] == pytest.approx(1_700_000_000.0)


def test_requires_some_payload():
    with pytest.raises(ValueError):
        build_session(None, None)


def test_generate_pcap_response_only_uses_dummy_request():
    raw_response = RESPONSE.decode()
    pkts = _read(generate_pcap(raw_response=raw_response, base_time=1_700_000_000.0))
    payloads = [bytes(p[Raw].load) for p in pkts if p.haslayer(Raw)]
    assert any(p.startswith(b"GET / HTTP/1.1") for p in payloads)
    assert RESPONSE in payloads


def test_generate_pcap_uses_host_header_port():
    raw_request = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
    pkts = _read(generate_pcap(raw_request=raw_request, base_time=1_700_000_000.0))
    assert all(p[TCP].dport == 8080 for p in pkts if p[IP].src == "10.10.10.1")


def test_generate_pcap_uses_host_header_ipv4_as_dst():
    raw_request = "GET / HTTP/1.1\r\nHost: 36.4.1.8:7001\r\n\r\n"
    pkts = _read(generate_pcap(raw_request=raw_request, base_time=1_700_000_000.0))
    client_pkts = [p for p in pkts if p[IP].src == "10.10.10.1"]
    assert all(p[IP].dst == "36.4.1.8" for p in client_pkts)
    assert all(p[TCP].dport == 7001 for p in client_pkts)


def test_generate_pcap_hostname_keeps_default_dst():
    raw_request = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
    pkts = _read(generate_pcap(raw_request=raw_request, base_time=1_700_000_000.0))
    client_pkts = [p for p in pkts if p[IP].src == "10.10.10.1"]
    assert all(p[IP].dst == "10.10.10.2" for p in client_pkts)


def test_generate_pcap_explicit_server_ip_wins():
    raw_request = "GET / HTTP/1.1\r\nHost: 36.4.1.8:7001\r\n\r\n"
    pkts = _read(
        generate_pcap(
            raw_request=raw_request,
            server_ip="192.168.1.5",
            base_time=1_700_000_000.0,
        )
    )
    client_pkts = [p for p in pkts if p[IP].src == "10.10.10.1"]
    assert all(p[IP].dst == "192.168.1.5" for p in client_pkts)
