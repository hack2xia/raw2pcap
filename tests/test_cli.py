from raw2pcap.cli import DEFAULT_PORT, build_parser, main


def test_serve_default_port():
    args = build_parser().parse_args(["serve"])
    assert args.port == DEFAULT_PORT == 5000
    assert args.host == "127.0.0.1"


def test_serve_port_override():
    args = build_parser().parse_args(["serve", "--port", "8080", "--host", "0.0.0.0"])
    assert args.port == 8080
    assert args.host == "0.0.0.0"


def test_generate_writes_pcap(tmp_path):
    req = tmp_path / "req.txt"
    out = tmp_path / "out.pcap"
    req.write_text("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")
    rc = main_with(["generate", str(req), "-o", str(out)])
    assert rc == 0
    assert out.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"


def main_with(argv):
    import sys
    from unittest import mock

    with mock.patch.object(sys, "argv", ["raw2pcap", *argv]):
        return main()
