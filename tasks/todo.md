# Tasks

- [x] Trace login → developer session → apptokens, and inspect issue #971 source/tests and the pinned isideload dependency.
- [x] Write regression tests covering transport, retry allowlist/limits, payload preservation, no auth/2FA/429/network retries, Retry-After, and client-info normalization; observe failures with original behavior (run 44910210708).
- [ ] Port transport and retry middleware, integrate before login, disable 429 retries, preserve settings; run focused and full Rust tests.
- [ ] Review the diff and mutation/negative controls; run frontend build and macOS Universal release build.
- [ ] Check both architectures, ad-hoc signatures, and native startup; assemble ZIP, source and concise Vietnamese report; verify ZIP CRC/SHA256.
