# V2 compatibility and security follow-up

This follow-up used synthetic data only. It did not access a personal account, saved session, contact list, or authenticated LINE service.

## Correction to the initial finding

The earlier fixture passed canonical-looking IDs such as `u` followed by 32 hexadecimal digits directly into Chrome's LTSM V2 API. That API expects authenticated, encoded MIDs and resolves them into canonical IDs before constructing authenticated message metadata. The fixture was invalid; its failure did not establish that account keys or the Go translation were incompatible.

The same invalid input fails in the original, unmodified Chrome WebAssembly module. Correctly encoded synthetic MIDs succeed in both that module and the Go client. The previous V1 fallback concealed this distinction and remains removed. A V2 failure is an error, never permission to substitute V1.

## Evidence and reproducibility

The public [LINE Chrome extension](https://chromewebstore.google.com/detail/line/ophjlpahpchlmihnnnihgmmeilfjmjjc), version 3.7.2, was downloaded from Google's extension update service for static inspection. Its version matches the client's target. No installed browser profile was used.

- Downloaded CRX SHA-256: `3722ab02edb0aba49c229399ee8df5b4b5a38c60b76efadadfbae395015eb859`
- Unmodified `ltsm.wasm` SHA-256: `58bb4e189ab9bbd7d72ed415258da36afd50e306cb019bab75329d4f5f1b65b3`

The official runtime consumes encoded MIDs. The standalone Go cipher consumes canonical lowercase IDs; the two interfaces must not be confused. Test encoded IDs were generated from repeating synthetic bytes, not copied from an account.

[LINE's encryption whitepaper](https://www.lycorp.co.jp/en/privacy-security/line-encryption-whitepaper-ver2.2.pdf) documents V2's authenticated metadata, key derivation, nonce and wire fields. Independent byte-level evidence and pinned reference revisions are recorded in the fixture generators under `pkg/ltsm/testdata`:

- `generate_v2_reference.py` generates fixed answers using Python cryptography and public RFC 7748 test keys.
- `generate_v2_official_reference.py` uses the unmodified public WASM and a hash-checked host shim, then independently checks its output with Python cryptography. It requires a separately downloaded public extension; the extension bundle is not redistributed here.

The checked-in fixture data is entirely synthetic. Normal Go tests consume fixed fixtures and do not download or execute external tools. Regenerating fixtures is a separate developer operation; follow each generator's instructions.

## What the tests establish

- The real manager encrypts a direct V2 message that an independent recipient cipher authenticates and decrypts using canonical IDs.
- The real manager completes a V2 group roundtrip. Altered sender, recipient and content-type metadata are rejected.
- Complete encrypted-file preparation uses the real manager and a fake network API; the recipient authenticates the sealed payload and attachment. Tampered payloads and files fail authentication.
- Original-WASM known answers corroborate cipher compatibility. Counters above 32 bits retain their full width across the runtime bridge.
- Messages labelled/defaulted to V2 cannot be accepted through V1 decryption. Explicit V1 remains supported; malformed framing and unknown versions are refused.

## Additional hardening

The bridge previously narrowed the 64-bit sequence counter to 32 bits. It now preserves all bits. The runner also no longer attempts to reinterpret opaque exported keys as raw private keys or silently select a different cipher implementation.

Malformed credential inputs previously escaped as generated-runtime panics. Bounded tests cover saved-key loading, login-keychain unwrapping, storage setup and storage decryption. Failures now return controlled errors without panic text or partial key registration. These are robustness findings: authenticated malformed keychain data or malformed decrypted session contents are required, rather than arbitrary passive network traffic.

The standalone canonical-ID cipher rejects malformed, uppercase, truncated or padded IDs rather than silently normalizing them into colliding authenticated metadata.

## Validation of this change

The core CLI/session/messaging/protocol/E2EE suite passed with the race detector. The separate runner and LTSM suites, vet, staticcheck v0.8.2, and formatting checks passed. The rebuilt Windows client and native Windows tests passed, including V2 interoperability, inbound downgrade rejection, malformed framing, and the 40-case credential-input corpus.

Govulncheck v1.9.0 reported no known reachable vulnerabilities in the source or rebuilt Windows executable. It also reported five module-level advisories whose affected code was not reached by this client. That result is not a security certification.

## Limits

These checks establish offline compatibility for the exercised paths, not production readiness or a complete independent cryptographic audit. Actual account login, saved-session restoration with account-issued keys, token refresh, group membership changes, live delivery and cloud-host recovery remain untested. Synthetic roundtrips cannot establish those behaviors. Personal-account tests remain separate from this review.
