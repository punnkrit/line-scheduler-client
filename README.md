# LINE Scheduler Client

A security-focused fork of [kongesque/line-cli](https://github.com/kongesque/line-cli), an unofficial command-line client for a personal LINE account. It can send messages to existing conversations without a LINE Official Account.

This repository currently provides the **sender**, not a complete hosted scheduler. A scheduling interface, durable job queue, and cloud deployment are separate work. Do not assume a message has been scheduled merely because this CLI is installed.

## Changes in this fork

- Build with Go **1.27.3**, which fixes the certificate-validation issue GO-2026-6809 present in the original v0.5.0 executable.
- Require Letter Sealing end-to-end encryption by default. An explicit `--require-e2ee=false` permits transport-only encryption when LINE reports that E2EE is unavailable.
- Fail when V2 direct-message encryption fails, instead of silently retrying with V1 while labelling the message V2. Explicitly negotiated V1 group support is preserved.
- Harden the build/update path so this fork's changes are not silently replaced by an upstream release.

**Known compatibility blocker:** the generated/transpiled-key V2 encryption path has a known upstream runtime failure. This fork refuses that send instead of substituting V1 ciphertext; compatibility with a real saved account session remains unverified.

These changes reduce specific risks; they do not certify the client as completely safe. See [review findings and limits](docs/FORK_SECURITY.md).

## Build from source

Install the exact Go 1.27.3 toolchain from [go.dev](https://go.dev/dl/). No administrator privileges or LINE credentials are needed to build.

```sh
git clone https://github.com/punnkrit/line-scheduler-client.git
cd line-scheduler-client
go mod verify
./build.sh
./bin/line version
```

On Windows, from PowerShell with Go 1.27.3 available:

```powershell
go mod verify
go build -trimpath -o .\bin\line.exe ./cmd/line
.\bin\line.exe version
```

Use this fork's source. The upstream Homebrew package and upstream install scripts do not include these changes. The included remote release installer entrypoints intentionally refuse upstream downloads and print source-build instructions.

## Sign in

```sh
./bin/line login --qr
```

Scan the QR code with LINE on your phone and approve the login. Keep the QR code and PIN private. QR login avoids typing a password into the CLI, but still grants a personal-client session. Email/password login is also supported; enter passwords only at the local hidden prompt.

The CLI stores session tokens and encryption keys using the operating system's credential protection. A Linux server without a desktop keyring requires the documented headless storage setup; ordinary desktop Linux and Windows have different requirements. See [session setup](docs/CLI.md#account-and-session).

Signing in can replace an existing Chrome-style LINE client session.

## Send a text

List conversations and identify the exact recipient before sending:

```sh
./bin/line chats --show-ids
./bin/line send CHAT_ID --text "A test message" --require-e2ee --timeout 30s
```

Use the full chat ID in automation. Names can be duplicated or changed. For text that should not appear in process arguments, supply UTF-8 text through standard input:

```sh
./bin/line send CHAT_ID --stdin --require-e2ee --json --timeout 30s < message.txt
```

Keep message input files outside the repository. The JSON receipt reports the message ID and encryption mode. A timeout or lost response can mean that a message was already sent: inspect the target conversation before retrying.

## Scheduling design

A future scheduler should persist each job's recipient, due time, status, and send receipt. It must distinguish a confirmed failure from an unknown delivery outcome. Blindly rerunning the CLI can produce duplicate messages, even though one CLI invocation does not replay a send automatically.

The CLI can run on demand; continuous desktop automation is not required by its architecture. Unattended login persistence and real delivery still need testing in the chosen host environment.

## Security and privacy

- This is an unofficial client with broad personal-account capabilities, not a token restricted to one chat or sending only.
- Treat the machine holding its session as trusted. OS credential encryption does not protect against every program running as the same user.
- No passwords, tokens, QR codes, private messages, contact lists, live captures, or session databases belong in this repository or in issue reports.
- All repository tests use synthetic data unless explicitly configured otherwise. Do not enable live-account tests in CI.
- The custom protocol/crypto runtime has not received a complete independent cryptographic audit. LINE changes can break compatibility, and this project cannot guarantee account-policy outcomes.

For current upstream features and limitations, see the [CLI guide](docs/CLI.md). Translated upstream guides may describe upstream defaults; this README defines this fork's security policy.

## Development

```sh
go test ./internal/... ./cmd/line ./pkg/line/... ./pkg/e2ee
go test ./pkg ./pkg/ltsm
./scripts/security-check.sh ./bin/line
```

Review upstream changes before integrating them. Keep the compiler security pin, dependency checksums, and encryption regression tests current.

## Attribution and license

This work builds on [Kongesque's LINE CLI](https://github.com/kongesque/line-cli) and its [Beeper LINE](https://github.com/beeper/line) origins. Upstream history and copyright notices are retained. The code remains under the [MIT License](LICENSE).

Not affiliated with or endorsed by LINE or LY Corporation.
