# iLoader 2.4.2 app-token transport patch

Port the transport and narrowly scoped retry behavior in iLoader issue #971, retaining the Mac OS X AuthKit override from SideStore #1745. Do not change saved settings, anisette defaults, storage, credentials or 2FA behavior.

## Decisions

- Install a GrandSlam client before calling account.login. Explicitly disable isideload's 429 retry setting and reqwest's built-in retries and redirects.
- Force HTTP/1.1, Connection: close, no idle pool, 15-second connect and 45-second request deadlines. Keep Apple Root trust and TLS validation.
- Retry only POST /grandslam/GsService2 with plist Request.o = apptokens, on 502/503/504, twice maximum. Preserve bytes/headers, 2/4-second backoff, respect Retry-After; stop if its wait exceeds 15 seconds. Never replay network errors, account authentication, passwords, verification codes or 429.
- Preserve the v2.4.2 fixed client override; normalize any remaining exact <macOS; OS component before use. No broad dependency upgrade or change to anisette selection.
- Add localhost regression tests and an expected-failure control against the original transport. CI runs the application test suite and builds a Universal macOS application.
- Use ad-hoc signing for this independent build because upstream Developer ID/notarization credentials are unavailable; document the scoped macOS Open Anyway install path.

## Order and verification

See tasks/todo.md. Trace and tests precede the fix. Tests and review gate the build. Inspect both Mach-O slices and signatures; smoke-test native startup on Intel and Apple Silicon. Package source, patch, logs, manifest, and DMG in a ZIP and verify all members after writing it. No real Apple ID credentials are available, so end-to-end authentication and sideload remain unverified.
