"""FastAPI web wrapper around raw2pcap.generate."""

import json
import re
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from raw2pcap.config import MAX_BODY_BYTES
from raw2pcap.generate import generate_pcap
from raw2pcap.parser import ParseError
from raw2pcap.selfcheck import SelfCheckError
from raw2pcap.synth import DEFAULT_CLIENT_IP, DEFAULT_SERVER_IP
from raw2pcap.validate import (
    IpValidationError,
    normalize_ipv4,
    validate_request,
    validate_response,
)

app = FastAPI(title="raw2pcap")

_STATIC = Path(__file__).parent / "static"
_INDEX_HTML = (_STATIC / "index.html").read_text(encoding="utf-8")
_APP_JS = (_STATIC / "app.js").read_bytes()

_ILLEGAL_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|]')


def _sanitize_filename(raw: str) -> str:
    """Turn the user-supplied name into a safe download filename.

    Sanitizing here (not in the browser) keeps all logic tested by pytest and
    guarantees a safe Content-Disposition header value: the stripped set
    includes both quote and backslash, so the result cannot break out of the
    quoted filename.
    """
    name = _ILLEGAL_FILENAME_CHARS.sub("", raw.strip()) or "raw2pcap-result"
    return name if name.lower().endswith(".pcap") else name + ".pcap"


def _utf8_bytes(*fields: str) -> int:
    """Sum the UTF-8 byte length of form fields (matches middleware accounting)."""
    return sum(len(f.encode("utf-8")) for f in fields)


def _resolve_ip(value: str, default: str, label: str) -> str:
    """Return *value* as a validated IPv4 address, or *default* when blank."""
    if not value.strip():
        return default
    try:
        return normalize_ipv4(value, label)
    except IpValidationError as exc:
        raise HTTPException(status_code=400, detail=[str(exc)]) from exc


def _form_text(field: str | UploadFile | None) -> str:
    """Normalize a multipart field that may arrive as text or as a file upload."""
    if field is None:
        return ""
    if hasattr(field, "filename"):  # UploadFile (starlette)
        try:
            return field.file.read().decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail=["input must be UTF-8 text"]) from None
    return field


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Reject oversized bodies early based on Content-Length.

    Chunked requests have no Content-Length; those are caught by the
    endpoint-level check on the parsed form fields.
    """
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": [f"request body too large (max {MAX_BODY_BYTES} bytes)"]},
        )
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _INDEX_HTML


@app.get("/static/app.js")
def app_js() -> Response:
    return Response(
        _APP_JS,
        media_type="text/javascript",
        headers={"Cache-Control": "no-cache"},
    )


@app.post("/api/pcap")
def create_pcap(
    inputRequest: Annotated[str | UploadFile | None, Form()] = None,
    inputResponse: Annotated[str | UploadFile | None, Form()] = None,
    filename: Annotated[str, Form()] = "",
    clientIp: Annotated[str, Form()] = "",
    serverIp: Annotated[str, Form()] = "",
) -> Response:
    input_request = _form_text(inputRequest)
    input_response = _form_text(inputResponse)
    if _utf8_bytes(input_request, input_response) > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail=[f"request body too large (max {MAX_BODY_BYTES} bytes)"],
        )
    if not input_request.strip():
        raise HTTPException(status_code=400, detail=["request is required"])
    issues = validate_request(input_request)
    if input_response.strip():
        issues += validate_response(input_response)
    errors = [i.message for i in issues if i.level == "error"]
    if errors:
        raise HTTPException(status_code=400, detail=errors)
    warnings = [i.message for i in issues if i.level == "warning"]

    try:
        pcap = generate_pcap(
            raw_request=input_request,
            raw_response=input_response,
            client_ip=_resolve_ip(clientIp, DEFAULT_CLIENT_IP, "client IP"),
            server_ip=_resolve_ip(serverIp, DEFAULT_SERVER_IP, "server IP"),
        )
    except (ValueError, ParseError) as exc:
        raise HTTPException(status_code=400, detail=[str(exc)]) from exc
    except SelfCheckError as exc:
        # The generated pcap failed its own round-trip verification - this is
        # a bug in the synthesizer, not in the user's input.
        raise HTTPException(status_code=500, detail=[f"pcap self-check failed: {exc}"]) from exc
    return Response(
        content=pcap,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="{_sanitize_filename(filename)}"',
            "X-Raw2pcap-Warnings": json.dumps(warnings),
        },
    )
