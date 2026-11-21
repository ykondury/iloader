"""Check official release artifacts and optionally probe GSA without credentials."""

import argparse
import hashlib
import json
import platform
import plistlib
import re
import ssl
import struct
import tarfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NOTARIZED_DMG = "notarized/universal-apple-darwin/release/bundle/dmg/iloader_2.4.2_universal.dmg"
HASHES = {
    "iloader-darwin-universal.dmg": "e67b92eeaf16493991c1721aec3e2aaedde6670a4fa4a546c111718340bf0680",
    "iloader-darwin-universal.app.tar.gz": "835f6d67281c2b1d774b749c96b9c9e67a6b45b9963c299cd87a4fbb08df9df6",
    "isideload-0.5.2.crate": "7cab6348bffd8f32c9358b80c8723bc1da45ad97b0c1f30a1533ade22d4d9496",
    "v2.4.1/iloader-darwin-universal.app.tar.gz": "cf4bdd269f91ae91651cd20b101c6217052bedd3ae06ead72ef04d611afcfa5b",
    NOTARIZED_DMG: "419e05f59ce8fe13a480dd27632e5b37530fd7964a7a8c8c5a3f010676ed6e67",
}
CLIENT_INFO = re.compile(
    rb"<[^<>\x00\r\n]+> <(?:macOS|Mac OS X);[^<>\x00\r\n]+> "
    rb"<com\.apple\.AuthKit/1 \(com\.apple\.akd/1\.0\)>"
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_members(path):
    with tarfile.open(path) as archive:
        selected = {}
        for suffix in ("/Contents/MacOS/iloader", "/Contents/Info.plist"):
            matches = [m for m in archive.getmembers() if m.isfile() and m.name.endswith(suffix)]
            if len(matches) != 1:
                raise ValueError(f"Expected exactly one archive member ending in {suffix}")
            selected[suffix] = archive.extractfile(matches[0]).read()
        return selected


def inspect_archive(path):
    members = archive_members(path)
    binary = members["/Contents/MacOS/iloader"]
    info = plistlib.loads(members["/Contents/Info.plist"])
    if binary[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("Expected a big-endian FAT Mach-O executable")
    count = struct.unpack_from(">I", binary, 4)[0]
    if count != 2:
        raise ValueError(f"Expected two Mach-O slices, got {count}")
    slices = []
    for index in range(count):
        cpu, subtype, offset, size, alignment = struct.unpack_from(">5I", binary, 8 + index * 20)
        if offset < 8 + count * 20 or size == 0 or offset + size > len(binary):
            raise ValueError("Invalid Mach-O slice bounds")
        payload = binary[offset:offset + size]
        slices.append({
            "architecture": {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cpu, hex(cpu)),
            "offset": offset,
            "bytes": size,
            "sha256": digest(payload),
            "authkit_client_info_strings": sorted({s.decode("ascii") for s in CLIENT_INFO.findall(payload)}),
        })
    return {
        "version": info.get("CFBundleShortVersionString"),
        "identifier": info.get("CFBundleIdentifier"),
        "minimum_macos": info.get("LSMinimumSystemVersion"),
        "executable_sha256": digest(binary),
        "slices": slices,
    }


def check_client_info(artifact):
    errors = []
    if {s["architecture"] for s in artifact["slices"]} != {"x86_64", "arm64"}:
        errors.append("Missing Intel or Apple Silicon slice")
    for item in artifact["slices"]:
        values = item["authkit_client_info_strings"]
        if not values or not any("<Mac OS X;" in value for value in values):
            errors.append(f"{item['architecture']}: no compatible AuthKit client info")
        if any("<macOS;" in value for value in values):
            errors.append(f"{item['architecture']}: rejected macOS OS label is embedded")
    return errors


def probe(client_info, context):
    request = urllib.request.Request(
        "https://gsa.apple.com/grandslam/GsService2",
        data=b"t",
        headers={"X-Mme-Client-Info": client_info,
                 "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    result = {"client_info": client_info, "credentials_sent": False}
    try:
        try:
            response = urllib.request.urlopen(request, context=context, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(4096)
            result.update(status=response.code, server=response.headers.get("Server"),
                          response_bytes_read=len(body), response_sha256=digest(body))
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        result.update(status=None, error=str(error))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--downloads", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--probe", action="store_true")
    args = parser.parse_args()
    report = {"checked_at": datetime.now(timezone.utc).isoformat(),
              "host": platform.platform(), "apple_id_login_verified": False}
    errors = []
    report["sha256"] = {}
    for name, expected in HASHES.items():
        actual = digest((args.downloads / name).read_bytes())
        report["sha256"][name] = {"actual": actual, "expected": expected, "match": actual == expected}
        if actual != expected:
            raise ValueError(f"SHA256 mismatch for {name}")

    source = (ROOT / "src-tauri/src/account.rs").read_bytes()
    matches = CLIENT_INFO.findall(source)
    if len(matches) != 1:
        raise ValueError("Expected exactly one AuthKit client info override in account.rs")
    source_client_info = matches[0].decode("ascii")
    report["source_client_info"] = source_client_info
    report["delivered_installer"] = {"path": NOTARIZED_DMG,
                                     "upstream_run": 44667757448,
                                     "upstream_artifact": 14598274773}
    report["release"] = inspect_archive(args.downloads / "iloader-darwin-universal.app.tar.gz")
    errors.extend(check_client_info(report["release"]))
    if report["release"]["version"] != "2.4.2":
        errors.append("Wrong application version")
    if report["release"]["identifier"] != "me.nabdev.iloader":
        errors.append("Wrong application identifier")
    for item in report["release"]["slices"]:
        if source_client_info not in item["authkit_client_info_strings"]:
            errors.append(f"{item['architecture']}: source override missing from executable")

    report["previous_release"] = inspect_archive(args.downloads / "v2.4.1/iloader-darwin-universal.app.tar.gz")
    if report["previous_release"]["version"] != "2.4.1":
        errors.append("Wrong negative-control version")
    for item in report["previous_release"]["slices"]:
        if not any("<macOS;" in value for value in item["authkit_client_info_strings"]):
            errors.append(f"{item['architecture']}: negative control lacks the old OS label")
    previous_errors = check_client_info(report["previous_release"])
    report["negative_control"] = {"version": "2.4.1", "rejected": bool(previous_errors),
                                  "errors": previous_errors}
    if not previous_errors:
        errors.append("Negative control did not detect the previous incompatible client info")

    if args.probe:
        # Match isideload's trust configuration; keep certificate and hostname verification enabled.
        with tarfile.open(args.downloads / "isideload-0.5.2.crate") as crate:
            certificate = crate.extractfile("isideload-0.5.2/src/assets/apple_root.cer").read()
        context = ssl.create_default_context()
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(certificate))
        report["additional_apple_root_sha256"] = digest(certificate)
        previous = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        values = [previous, previous.replace("<macOS;", "<Mac OS X;"), source_client_info]
        report["accountless_probes"] = [probe(value, context) for value in values]
        statuses = [item["status"] for item in report["accountless_probes"]]
        report["edge_comparison"] = "503_to_401_observed" if statuses == [503, 401, 401] else "inconclusive"

    report["artifact_checks_passed"] = not errors
    report["artifact_errors"] = errors
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
