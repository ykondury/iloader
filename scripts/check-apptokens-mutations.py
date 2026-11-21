"""Verify retry safety tests fail when their production guards are removed."""

import json
import subprocess
from pathlib import Path


source = Path("src-tauri/src/apple_auth.rs")
original = source.read_bytes()
text = original.decode("utf-8")
output = Path("results")
output.mkdir(exist_ok=True)
mutations = [
    ("retry-429", "StatusCode::GATEWAY_TIMEOUT", "StatusCode::TOO_MANY_REQUESTS",
     "apple_auth::tests::statuses_outside_the_gateway_allowlist_are_never_retried"),
    ("retry-authentication", "if !is_token_request(&request) {", "if false {",
     "apple_auth::tests::authentication_password_and_2fa_operations_are_never_retried"),
]
results = []
try:
    for name, needle, replacement, test in mutations:
        if text.count(needle) != 1:
            raise ValueError(f"Mutation {name} must change exactly one guard")
        source.write_text(text.replace(needle, replacement), encoding="utf-8")
        process = subprocess.run([
            "cargo", "test", "--manifest-path", "src-tauri/Cargo.toml", "--locked",
            "--release", "--target", "aarch64-apple-darwin", "--lib", test,
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / f"mutation-{name}.log").write_bytes(process.stdout)
        caught = process.returncode != 0 and b"test result: FAILED" in process.stdout
        results.append({"mutation": name, "caught_by_test": caught})
        if not caught:
            raise ValueError(f"Regression did not catch mutation: {name}")
finally:
    source.write_bytes(original)
    (output / "mutations.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
assert source.read_bytes() == original
print(json.dumps(results, indent=2))
