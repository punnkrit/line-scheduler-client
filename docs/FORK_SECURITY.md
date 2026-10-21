# Fork security review

A bounded review of upstream v0.5.0 (commit aeefb35735ce496093fa0f8b7e76303c77a63e32) was performed on 2026-10-21 before attempting personal-account use. This document describes evidence and limits, not a security certification.

## Findings addressed in this fork

1. **Outdated certificate validation:** the upstream Windows executable was built with Go 1.27.2. A local govulncheck v1.9.0 binary scan flagged GO-2026-6809 in crypto/x509.Certificate.Verify. Go 1.27.3 adds distrust of affected intermediate certificates in cases where system trust updates do not suffice. This finding does not imply observed exploitation. The fork updates the compiler pin and build instructions. [Go advisory](https://vuln.go.dev/ID/GO-2026-6809.json)
2. **Encryption default:** upstream CLI send options allowed transport-only delivery by default following explicit LINE capability signals. This fork requires end-to-end encryption by default; transport-only delivery requires an explicit opt-out.
3. **V2 fallback inconsistency:** direct-message encryption could retry V1 after a V2 failure while the enclosing sender still declared V2. This fork preserves the V2 failure instead. The generated/transpiled-key V2 path fails authentication inside the upstream runtime, and an upstream attachment test had accepted its V1 fallback. This fork treats that path as unsupported and refuses the send. This was a protocol/downgrade finding, not demonstrated plaintext exposure; fixing the generated cryptographic runtime is outside this review.
4. **Build/update trust:** upstream Windows releases and tags were unsigned, and Actions references used mutable major tags. Checksums provide integrity relative to the publisher, not independent authentication. This fork pins Actions references and prevents its managed builds from replacing themselves with upstream releases.

## Positive evidence

- An independent Go 1.27.2 rebuild of the audited upstream source and the downloaded upstream executable differed only in 40 bytes within Go build-action-ID metadata. All remaining bytes matched, including code and embedded data. This is strong source/release consistency evidence, not proof of benign behavior.
- Windows session storage uses user-scoped DPAPI. Saved state contains tokens/certificates/encryption keys but no password field. Login output suppresses raw server responses.
- Reviewed LINE request paths use fixed HTTPS LINE hosts and reject redirects. No obvious third-party credential collection or telemetry was found in the inspected first-party runtime paths.
- Strict encryption refusal and duplicate-send protections have regression coverage. Synthetic session, messaging, update, CLI and protocol tests passed during the upstream audit.

## Fork validation

- Core CLI, session, messaging, updater, protocol and E2EE suites passed with the race detector under Go 1.27.3; vet and staticcheck v0.8.2 passed.
- Source and rebuilt Windows-binary govulncheck v1.9.0 scans reported no known reachable vulnerabilities at review time.
- Generated-key text and file regressions assert refusal without a message send. File preparation may already have uploaded encrypted bytes; the failure reports that outcome.
- A separate test authenticates a V2 payload and attachment with the pure-Go cipher, including tamper rejection. It does **not** validate the full account-key/manager path. The old test's acceptance of V1 ciphertext as V2 was removed.

## Remaining trust boundaries

The session has personal-client authority; a wrapper restricting the selected recipient cannot narrow the underlying token. Code or a host that can decrypt that session can act beyond a scheduling task. This review does not establish access to unrelated services linked to LINE, nor does it establish that such services are isolated from every possible account compromise.

The cryptographic runtime includes generated Go and embedded memory tables. Their integration was reviewed, but the entire generated implementation and every dependency were not formally audited. A clean vulnerability scan detects known issues, not all malicious behavior or protocol flaws.

No authenticated production login, live message capture, or live send was needed for this review. Native Windows DPAPI tests with temporary synthetic sessions passed, including replacement, tamper rejection, and non-destructive preflight. Other host credential stores, long-term token refresh, real account-key compatibility, exact delivery behavior, and host reboot recovery need separate environment-specific validation. Do not claim a scheduler is production-ready from these checks alone.

A send may register a group encryption key when required. A scheduler must retain durable job state and stop for reconciliation after uncertain delivery; retrying the whole process can duplicate a message.

## Reporting

Report source-level defects with synthetic reproduction data. Never attach a real QR code, session file, token, password, private conversation, or raw authenticated traffic. For sensitive findings, use the upstream project's security contact rather than posting private material publicly.
