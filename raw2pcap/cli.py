"""Command-line interface for raw2pcap.

Usage:
    raw2pcap generate [request.req] [response.res] -o out.pcap
    raw2pcap serve [--host HOST] [--port PORT]
"""

import argparse
import sys

from raw2pcap.generate import generate_pcap
from raw2pcap.parser import ParseError
from raw2pcap.synth import DEFAULT_CLIENT_IP, DEFAULT_SERVER_IP
from raw2pcap.validate import IpValidationError, normalize_ipv4

DEFAULT_PORT = 5000


def _ipv4_type(label: str):
    """Build an argparse type that validates a value as a usable IPv4 address."""

    def convert(value: str) -> str:
        try:
            return normalize_ipv4(value, label)
        except IpValidationError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from None

    return convert


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raw2pcap",
        description="Create pcap files from raw HTTP request/response text.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen = subparsers.add_parser("generate", help="create a pcap from raw HTTP text files")
    gen.add_argument("request", nargs="?", help="file containing a raw HTTP request")
    gen.add_argument("response", nargs="?", help="file containing a raw HTTP response")
    gen.add_argument("-o", "--output", default="raw2pcap-result.pcap")
    gen.add_argument(
        "--client-ip",
        type=_ipv4_type("client IP"),
        default=DEFAULT_CLIENT_IP,
        help=f"client (source) IPv4 address [default {DEFAULT_CLIENT_IP}]",
    )
    gen.add_argument(
        "--server-ip",
        type=_ipv4_type("server IP"),
        default=None,
        help="server (destination) IPv4 address [default: literal IPv4 from "
        f"the Host header, else {DEFAULT_SERVER_IP}]",
    )

    serve = subparsers.add_parser("serve", help="run the web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    return parser


def _cmd_generate(args: argparse.Namespace) -> int:
    raw_request = None
    raw_response = None
    if args.request:
        with open(args.request, encoding="utf-8") as f:
            raw_request = f.read()
    if args.response:
        with open(args.response, encoding="utf-8") as f:
            raw_response = f.read()

    try:
        pcap = generate_pcap(
            raw_request=raw_request,
            raw_response=raw_response,
            client_ip=args.client_ip,
            server_ip=args.server_ip,
        )
    except (ValueError, ParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    with open(args.output, "wb") as f:
        f.write(pcap)
    print(f"wrote {args.output} ({len(pcap)} bytes)")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from raw2pcap.config import LIMIT_CONCURRENCY

    uvicorn.run(
        "raw2pcap.api:app",
        host=args.host,
        port=args.port,
        # Generating a pcap is CPU/memory heavy; keep concurrency low. Bulk
        # generation should use the CLI, not this web API.
        limit_concurrency=LIMIT_CONCURRENCY,
    )
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "serve":
        return _cmd_serve(args)
    return _cmd_generate(args)


if __name__ == "__main__":
    sys.exit(main())
