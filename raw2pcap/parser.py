"""Parse raw HTTP request/response text into structured messages.

Parsing is deliberately lenient: the goal is to reproduce the bytes the user
pasted, not to validate them against the RFC.
"""

from dataclasses import dataclass, field

CRLF = "\r\n"
HEADER_SEP = CRLF + CRLF


class ParseError(ValueError):
    """Raised when raw HTTP text cannot be parsed."""


def split_head_body(text: str) -> tuple[str, bytes]:
    """Split raw text into the head (start line + headers) and raw body bytes."""
    if HEADER_SEP in text:
        head, body = text.split(HEADER_SEP, 1)
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    return head, body.encode("utf-8")


def _parse_head(head: str) -> tuple[str, list[tuple[str, str]]]:
    lines = head.replace("\r\n", "\n").split("\n")
    start_line = lines[0].strip()
    if not start_line:
        raise ParseError("empty start line")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise ParseError(f"malformed header line: {line!r}")
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return start_line, headers


@dataclass
class HttpMessage:
    """Common fields of an HTTP request or response."""

    version: str = "HTTP/1.1"
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        """Return the first header value matching *name* (case-insensitive)."""
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def head_bytes(self, start_line: str) -> bytes:
        """Serialize the start line and headers, fixing Content-Length if needed."""
        headers = list(self.headers)
        has_length = any(k.lower() == "content-length" for k, _ in headers)
        has_chunked = (self.header("transfer-encoding") or "").lower() == "chunked"
        if self.body and not has_length and not has_chunked:
            headers.append(("Content-Length", str(len(self.body))))
        lines = [start_line] + [f"{k}: {v}" for k, v in headers]
        return CRLF.join(lines).encode("utf-8") + HEADER_SEP.encode("utf-8")


@dataclass
class HttpRequest(HttpMessage):
    """A parsed HTTP request."""

    method: str = "GET"
    path: str = "/"

    def host_port(self, default_port: int = 80) -> int:
        """Return the server port taken from the Host header."""
        host = self.header("host") or ""
        if ":" in host:
            try:
                port = int(host.rsplit(":", 1)[1])
            except ValueError as exc:
                raise ParseError(f"invalid port in Host header: {host!r}") from exc
            if not 1 <= port <= 65535:
                raise ParseError(f"invalid port in Host header: {host!r}")
            return port
        return default_port

    def to_bytes(self) -> bytes:
        start_line = f"{self.method} {self.path} {self.version}"
        return self.head_bytes(start_line) + self.body


@dataclass
class HttpResponse(HttpMessage):
    """A parsed HTTP response."""

    status: int = 200
    reason: str = "OK"

    def to_bytes(self) -> bytes:
        start_line = f"{self.version} {self.status} {self.reason}"
        return self.head_bytes(start_line) + self.body


def parse_request(text: str) -> HttpRequest:
    """Parse raw HTTP request text."""
    if not text or not text.strip():
        raise ParseError("empty request")
    head, body = split_head_body(text)
    start_line, headers = _parse_head(head)
    parts = start_line.split(" ", 2)
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise ParseError(f"malformed request line: {start_line!r}")
    method, path = parts[0], parts[1]
    version = parts[2]
    return HttpRequest(version=version, headers=headers, body=body, method=method, path=path)


def parse_response(text: str) -> HttpResponse:
    """Parse raw HTTP response text."""
    if not text or not text.strip():
        raise ParseError("empty response")
    head, body = split_head_body(text)
    start_line, headers = _parse_head(head)
    parts = start_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ParseError(f"malformed status line: {start_line!r}")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise ParseError(f"malformed status code: {start_line!r}") from exc
    reason = parts[2] if len(parts) == 3 else ""
    return HttpResponse(version=parts[0], headers=headers, body=body, status=status, reason=reason)
