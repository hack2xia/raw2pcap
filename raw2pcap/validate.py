"""Pre-generation validation of raw HTTP text.

The parser is deliberately lenient so it can reproduce pasted bytes; this
module is the strict gate that runs *before* pcap synthesis. Errors block
generation (HTTP 400), warnings are returned alongside the pcap so the UI
can show them.
"""

import re
from dataclasses import dataclass

from raw2pcap.parser import HEADER_SEP, split_head_body

_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_BLANK_WITH_WS_RE = re.compile(r"(?:\r\n|\n)[ \t]+(?:\r\n|\n)")


@dataclass
class Issue:
    level: str  # "error" or "warning"
    message: str


def _check_head(text: str, kind: str) -> tuple[list[Issue], list[str], bytes]:
    """Shared checks on the start-line/headers region.

    Returns (issues, header lines, body bytes).
    """
    issues: list[Issue] = []

    # The header/body separator must be a completely empty line. A separator
    # like "\r\n \r\n" would silently glue the body onto the headers.
    if HEADER_SEP not in text and "\n\n" not in text and _BLANK_WITH_WS_RE.search(text):
        issues.append(
            Issue(
                "error",
                f"{kind}: the blank line between headers and body must be "
                "completely empty (it starts with a space or tab)",
            )
        )

    head, body = split_head_body(text)
    lines = head.replace("\r\n", "\n").split("\n")
    for line in lines[1:]:
        if not line.strip():
            continue
        if line[0] in " \t":
            issues.append(
                Issue(
                    "error",
                    f"{kind}: header line starts with whitespace: {line.strip()!r} "
                    "(obsolete line folding; join it onto the previous header)",
                )
            )
            continue
        name, sep, _ = line.partition(":")
        if not sep:
            issues.append(Issue("error", f"{kind}: malformed header line (no ':'): {line!r}"))
            continue
        if not _TOKEN_RE.match(name.strip()):
            issues.append(Issue("error", f"{kind}: invalid header name: {name.strip()!r}"))
    return issues, lines, body


def _check_body_framing(
    issues: list[Issue], headers: list[tuple[str, str]], body: bytes, kind: str
) -> None:
    lengths = [v for k, v in headers if k.lower() == "content-length"]
    chunked = any(k.lower() == "transfer-encoding" and "chunked" in v.lower() for k, v in headers)
    if chunked:
        # We embed the pasted bytes verbatim; decoding/re-encoding chunked
        # bodies is out of scope, so reject them outright.
        issues.append(
            Issue(
                "error",
                f"{kind}: Transfer-Encoding: chunked is not supported; "
                "paste the decoded body with a Content-Length header instead",
            )
        )
    if len(lengths) > 1:
        issues.append(
            Issue(
                "error",
                f"{kind}: multiple Content-Length headers ({len(lengths)}) are not "
                "allowed - ambiguous request framing is a request-smuggling signal",
            )
        )
    elif lengths:
        try:
            declared = int(lengths[-1])
        except ValueError:
            issues.append(
                Issue("error", f"{kind}: Content-Length is not a number: {lengths[-1]!r}")
            )
        else:
            if declared != len(body):
                issues.append(
                    Issue(
                        "warning",
                        f"{kind}: Content-Length is {declared} but the body is {len(body)} bytes",
                    )
                )


def _headers_of(lines: list[str]) -> list[tuple[str, str]]:
    headers = []
    for line in lines[1:]:
        if line.strip() and ":" in line and line[0] not in " \t":
            name, _, value = line.partition(":")
            headers.append((name.strip(), value.strip()))
    return headers


def _check_host_port(
    issues: list[Issue], headers: list[tuple[str, str]], kind: str
) -> None:
    """Reject Host headers whose port is missing, non-numeric, or out of range.

    The parser turns the Host port into the TCP destination port; an invalid
    value would otherwise surface as an opaque Scapy struct.error at build
    time instead of a clear validation message here.
    """
    for name, value in headers:
        if name.lower() != "host":
            continue
        if value.startswith("["):
            # IPv6 literal: "[::1]" or "[::1]:8080". Sessions are IPv4-only,
            # but an explicit port is still validated when present.
            match = re.match(r"^\[[^\]]+\](?::(\d*))?$", value)
            if not match:
                issues.append(Issue("error", f"{kind}: malformed Host header: {value!r}"))
                continue
            port = match.group(1)
            if port is None:
                continue
        elif ":" not in value:
            continue
        else:
            port = value.rsplit(":", 1)[1]
        if port == "":
            issues.append(Issue("error", f"{kind}: Host header has an empty port: {value!r}"))
            continue
        if not port.isdigit():
            issues.append(Issue("error", f"{kind}: Host port is not a number: {value!r}"))
            continue
        port_num = int(port)
        if not 1 <= port_num <= 65535:
            issues.append(
                Issue(
                    "error",
                    f"{kind}: Host port {port_num} is out of range (must be 1-65535)",
                )
            )


def validate_request(text: str) -> list[Issue]:
    """Validate raw HTTP request text before pcap generation."""
    issues, lines, body = _check_head(text, "request")
    headers = _headers_of(lines)
    version = lines[0].strip().split(" ")[-1] if lines else ""
    if version == "HTTP/1.1" and not any(k.lower() == "host" for k, _ in headers):
        issues.append(Issue("error", "request: HTTP/1.1 request is missing the Host header"))
    _check_host_port(issues, headers, "request")
    _check_body_framing(issues, headers, body, "request")
    return issues


def validate_response(text: str) -> list[Issue]:
    """Validate raw HTTP response text before pcap generation."""
    issues, lines, body = _check_head(text, "response")
    _check_body_framing(issues, _headers_of(lines), body, "response")
    return issues
