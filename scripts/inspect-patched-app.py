"""Inspect a locally built macOS app without executing its code."""

import argparse
import hashlib
import json
import plistlib
import re
import struct
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("app", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
binary = (args.app / "Contents/MacOS/iloader").read_bytes()
info = plistlib.loads((args.app / "Contents/Info.plist").read_bytes())
if binary[:4] != b"\xca\xfe\xba\xbe" or struct.unpack_from(">I", binary, 4)[0] != 2:
    raise ValueError("Expected a Universal Mach-O with two CPU slices")
pattern = re.compile(rb"<[^<>\x00\r\n]+> <(?:macOS|Mac OS X);[^<>\x00\r\n]+> <com\.apple\.AuthKit/1 \(com\.apple\.akd/1\.0\)>")
slices = []
for index in range(2):
    cpu, subtype, offset, size, alignment = struct.unpack_from(">5I", binary, 8 + index * 20)
    if offset < 48 or size == 0 or offset + size > len(binary):
        raise ValueError("Invalid CPU slice bounds")
    payload = binary[offset:offset + size]
    strings = sorted({value.decode("ascii") for value in pattern.findall(payload)})
    if not strings or any("<macOS;" in value for value in strings):
        raise ValueError("Incorrect AuthKit client-info OS label")
    if b"Retrying Apple developer-token request" not in payload:
        raise ValueError("The patched retry middleware is missing from the executable")
    slices.append({"architecture": {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cpu),
                   "bytes": size, "sha256": hashlib.sha256(payload).hexdigest(),
                   "authkit_client_info": strings, "retry_middleware_marker": True})
if {item["architecture"] for item in slices} != {"x86_64", "arm64"}:
    raise ValueError("Missing Intel or Apple Silicon executable")
report = {"version": info.get("CFBundleShortVersionString"),
          "identifier": info.get("CFBundleIdentifier"),
          "executable_sha256": hashlib.sha256(binary).hexdigest(),
          "slices": slices, "apple_id_login_verified": False}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
