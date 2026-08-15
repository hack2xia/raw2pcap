"""Synthesize a TCP session carrying HTTP payloads and write it as pcap.

Everything is built in memory with Scapy: a three-way handshake, payload
segments split by MSS (each acknowledged), and a four-way close. Checksums
are computed by Scapy at serialization time.
"""

import time
from io import BytesIO

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

DEFAULT_CLIENT_IP = "10.10.10.1"
DEFAULT_SERVER_IP = "10.10.10.2"
DEFAULT_MSS = 1460

_CLIENT_MAC = "02:00:00:00:00:01"
_SERVER_MAC = "02:00:00:00:00:02"


class _Session:
    """Tracks sequence numbers and emits packets for one TCP connection."""

    def __init__(
        self,
        client_ip: str,
        server_ip: str,
        client_port: int,
        server_port: int,
        base_time: float,
        client_isn: int,
        server_isn: int,
        mss: int,
    ) -> None:
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.time = base_time
        self.c_seq = client_isn
        self.s_seq = server_isn
        self.mss = mss
        self.packets: list = []

    def _tick(self, delta: float) -> None:
        self.time += delta

    def _emit(self, src_client: bool, flags: str, payload: bytes = b"") -> None:
        if src_client:
            src, dst = self.client_ip, self.server_ip
            sport, dport = self.client_port, self.server_port
            seq, ack = self.c_seq, self.s_seq
            eth = Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        else:
            src, dst = self.server_ip, self.client_ip
            sport, dport = self.server_port, self.client_port
            seq, ack = self.s_seq, self.c_seq
            eth = Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
        pkt = (
            eth
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=64240)
        )
        if payload:
            pkt = pkt / Raw(load=payload)
        pkt.time = self.time
        self.packets.append(pkt)
        advance = 1 if "S" in flags or "F" in flags else 0
        advance += len(payload)
        if src_client:
            self.c_seq += advance
        else:
            self.s_seq += advance

    def handshake(self) -> None:
        self._emit(src_client=True, flags="S")
        self._tick(0.0001)
        self._emit(src_client=False, flags="SA")
        self._tick(0.0001)
        self._emit(src_client=True, flags="A")

    def send(self, from_client: bool, data: bytes) -> None:
        """Send *data* in MSS-sized segments, each one acknowledged."""
        offset = 0
        while offset < len(data):
            segment = data[offset : offset + self.mss]
            self._tick(0.0002)
            self._emit(src_client=from_client, flags="PA", payload=segment)
            self._tick(0.0001)
            self._emit(src_client=not from_client, flags="A")
            offset += len(segment)

    def close(self) -> None:
        self._tick(0.0002)
        self._emit(src_client=True, flags="FA")
        self._tick(0.0001)
        self._emit(src_client=False, flags="A")
        self._tick(0.0001)
        self._emit(src_client=False, flags="FA")
        self._tick(0.0001)
        self._emit(src_client=True, flags="A")


def build_session(
    request: bytes | None,
    response: bytes | None,
    *,
    client_ip: str = DEFAULT_CLIENT_IP,
    server_ip: str = DEFAULT_SERVER_IP,
    client_port: int = 50000,
    server_port: int = 80,
    base_time: float | None = None,
    client_isn: int = 1000,
    server_isn: int = 5000,
    mss: int = DEFAULT_MSS,
) -> bytes:
    """Build a pcap (as bytes) of a TCP session carrying request then response.

    At least one of *request* / *response* must be provided.
    """
    if not request and not response:
        raise ValueError("at least one of request/response must be provided")
    session = _Session(
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=client_port,
        server_port=server_port,
        base_time=base_time if base_time is not None else time.time(),
        client_isn=client_isn,
        server_isn=server_isn,
        mss=mss,
    )
    session.handshake()
    if request:
        session.send(from_client=True, data=request)
    if response:
        session.send(from_client=False, data=response)
    session.close()

    buf = BytesIO()
    # Do not close the writer: PcapWriter.close() would close the buffer too.
    writer = PcapWriter(buf, sync=True)
    for pkt in session.packets:
        writer.write(pkt)
    writer.flush()
    return buf.getvalue()
