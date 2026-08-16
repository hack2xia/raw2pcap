import pytest

from raw2pcap.parser import ParseError, parse_request, parse_response

REQUEST = (
    "POST /login?a=1 HTTP/1.1\r\n"
    "Host: example.com:8080\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 11\r\n"
    "\r\n"
    "user=root&x"
)

RESPONSE = "HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 9\r\n\r\nnot found"


def test_parse_request_fields():
    req = parse_request(REQUEST)
    assert req.method == "POST"
    assert req.path == "/login?a=1"
    assert req.version == "HTTP/1.1"
    assert req.header("content-type") == "application/x-www-form-urlencoded"
    assert req.body == b"user=root&x"


def test_parse_request_host_port():
    assert parse_request(REQUEST).host_port() == 8080
    no_port = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert parse_request(no_port).host_port() == 80


def test_parse_request_host_name():
    cases = {
        "example.com:8080": "example.com",
        "36.4.1.8:7001": "36.4.1.8",
        "[::1]:8080": "[::1]",
        "example.com": "example.com",
    }
    for host, expected in cases.items():
        raw = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        assert parse_request(raw).host_name() == expected


def test_request_roundtrip_bytes():
    req = parse_request(REQUEST)
    assert req.to_bytes() == REQUEST.encode("utf-8")


def test_request_adds_content_length_when_missing():
    raw = "POST / HTTP/1.1\r\nHost: x\r\n\r\nabc"
    out = parse_request(raw).to_bytes()
    assert b"Content-Length: 3\r\n" in out
    assert out.endswith(b"abc")


def test_parse_response_fields():
    resp = parse_response(RESPONSE)
    assert resp.status == 404
    assert resp.reason == "Not Found"
    assert resp.header("server") == "nginx"
    assert resp.body == b"not found"
    assert resp.to_bytes() == RESPONSE.encode("utf-8")


@pytest.mark.parametrize(
    "text",
    ["", "   ", "garbage", "GET\r\nHost: x\r\n\r\n", "GET / HTTP/1.1\r\nBadHeaderLine\r\n\r\n"],
)
def test_parse_request_rejects_garbage(text):
    with pytest.raises(ParseError):
        parse_request(text)


def test_parse_response_rejects_bad_status():
    with pytest.raises(ParseError):
        parse_response("HTTP/1.1 abc Bad\r\n\r\n")


@pytest.mark.parametrize(
    "host",
    ["example.com:0", "example.com:99999", "example.com:abc", "example.com:"],
)
def test_parse_request_rejects_bad_host_port(host):
    with pytest.raises(ParseError):
        parse_request(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").host_port()
