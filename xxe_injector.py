#!/usr/bin/env python3
"""Safely check an explicitly authorized XML endpoint with a benign baseline."""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE_BYTES = 16 * 1024
MAX_TIMEOUT_SECONDS = 30.0
MAX_URL_BYTES = 2048
MAX_HEADERS = 16
MAX_HEADER_BYTES = 8 * 1024
HEADER_NAME_CHARS = "!#$%&'*+-.^_`|~"

SAFE_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b"<root><message>safe-xml-baseline</message></root>"
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_target(url: str) -> None:
    if len(url.encode("utf-8")) > MAX_URL_BYTES:
        raise ValueError(f"target URL exceeds {MAX_URL_BYTES} bytes")
    if any(ord(char) <= 32 or ord(char) == 127 for char in url):
        raise ValueError("target URL must not contain whitespace or control characters")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target URL is invalid") from exc

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an absolute HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URLs must not contain credentials")
    if parsed.fragment:
        raise ValueError("target URL must not contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("target port is invalid")


def parse_headers(values: list[str]) -> dict[str, str]:
    if len(values) > MAX_HEADERS:
        raise ValueError(f"at most {MAX_HEADERS} request headers are allowed")

    headers = {}
    total_bytes = 0
    reserved = {
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "host",
        "transfer-encoding",
        "user-agent",
    }
    for value in values:
        if ":" not in value:
            raise ValueError("headers must use the format 'Name: Value'")
        name, header_value = value.split(":", 1)
        name = name.strip()
        header_value = header_value.strip()
        if not name or not all(
            char.isascii() and (char.isalnum() or char in HEADER_NAME_CHARS)
            for char in name
        ):
            raise ValueError("header names must use valid ASCII HTTP token characters")
        if any(
            (ord(char) < 32 and char != "\t") or ord(char) > 255 or ord(char) == 127
            for char in header_value
        ):
            raise ValueError("header values contain unsupported control or non-Latin-1 characters")
        if name.lower() in reserved:
            raise ValueError(f"header '{name}' is controlled by the tool")
        if any(existing.lower() == name.lower() for existing in headers):
            raise ValueError(f"duplicate request header: {name}")
        total_bytes += len(name.encode("utf-8")) + len(header_value.encode("utf-8"))
        if total_bytes > MAX_HEADER_BYTES:
            raise ValueError(f"combined request headers exceed {MAX_HEADER_BYTES} bytes")
        headers[name] = header_value
    return headers


def _read_bounded(response) -> tuple[str, bool]:
    raw_body = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(raw_body) > MAX_RESPONSE_BYTES
    body = raw_body[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    return body, truncated


def send_baseline(url: str, extra_headers: dict[str, str], timeout: float) -> dict:
    validate_target(url)
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    extra_headers = parse_headers(
        [f"{name}: {value}" for name, value in extra_headers.items()]
    )
    request = urllib.request.Request(url, data=SAFE_XML, method="POST")
    request.add_header("Content-Type", "application/xml")
    request.add_header("User-Agent", "XXEInjector-SafeBaseline/1.0")
    for name, value in extra_headers.items():
        request.add_header(name, value)

    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            body, truncated = _read_bounded(response)
            return {
                "status_code": response.status,
                "content_type": response.headers.get("Content-Type"),
                "response_excerpt": body,
                "response_truncated": truncated,
            }
    except urllib.error.HTTPError as exc:
        with exc:
            body, truncated = _read_bounded(exc)
        return {
            "status_code": exc.code,
            "content_type": exc.headers.get("Content-Type"),
            "response_excerpt": body,
            "response_truncated": truncated,
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "transport_error": str(exc.reason if isinstance(exc, urllib.error.URLError) else exc),
        }


def run_check(url: str, headers: dict[str, str], timeout: float) -> dict:
    validate_target(url)
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    headers = parse_headers([f"{name}: {value}" for name, value in headers.items()])

    observation = send_baseline(url, headers, timeout)
    return {
        "tool": "xxe-injector-safe-baseline",
        "target": url,
        "probe": "One fixed, well-formed XML document without a DTD or entity declarations.",
        "request_count": 1,
        "limits": {
            "socket_timeout_seconds": timeout,
            "timeout_is_total_deadline": False,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "redirects_followed": 0,
        },
        "observation": observation,
        "conclusion": (
            "This records only the HTTP behavior for the benign baseline. "
            "It does not test or prove whether XXE is present or absent."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Send one bounded, benign XML baseline to an explicitly authorized endpoint.",
        epilog=(
            "This tool does not send DTD/entity payloads and cannot determine whether an endpoint "
            "is vulnerable to XXE. Use only against the exact authorized URL."
        ),
    )
    parser.add_argument("url", help="Exact HTTP(S) endpoint to check")
    parser.add_argument(
        "--authorized-target", required=True,
        help="Repeat the exact URL to confirm the authorized target scope",
    )
    parser.add_argument(
        "--i-have-authorization", action="store_true",
        help="Confirm you are authorized to send a request to this endpoint",
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="Socket inactivity timeout in seconds (maximum 30)",
    )
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE")
    parser.add_argument("--out", help="Write the JSON observation to this file")
    args = parser.parse_args(argv)

    if not args.i_have_authorization:
        parser.error("pass --i-have-authorization only when you are authorized to test this endpoint")
    if args.url != args.authorized_target:
        parser.error("--authorized-target must exactly match the URL")

    try:
        headers = parse_headers(args.header)
        report = run_check(args.url, headers, args.timeout)
    except ValueError as exc:
        parser.error(str(exc))

    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as output:
                output.write(rendered + "\n")
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
