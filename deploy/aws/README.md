# Serverless LINE scheduler

A single-owner scheduler for the reviewed personal-account LINE client.
The private Sites UI talks to a token-protected Lambda function URL. EventBridge
Scheduler invokes a separate sender Lambda. No always-on computer, VM, or AI
agent is involved in scheduled execution.

## What is implemented

- Immediate text sending and one-time scheduled sends, cancellation, and history.
- UTC schedule storage with explicit time-zone selection in the interface.
- Letter Sealing is mandatory. No plaintext downgrade or send retries.
- Durable jobs and session state in separate DynamoDB tables.
- AES-256-GCM encrypted session records, authenticated with a versioned context.
- A 180-second database lease serializes the account. The Lambda timeout is
  120 seconds and the child command deadline is 80 seconds.
- Session saves atomically check the lease owner, lease expiry, and version.
  The Go client waits for the database acknowledgement before sending.
- Conditional job claims stop duplicate invocations. An uncertain response is
  marked **Check LINE**, never automatically sent again.
- SQS catches failed asynchronous delivery. Jobs more than 15 minutes late
  expire rather than sending unexpectedly later.
- Seven-day infrastructure logs; messages expire 90 days after their due time
  through DynamoDB TTL (physical deletion is asynchronous).

This is unofficial LINE integration. LINE can invalidate the session or change
its protocol. A confirmed receipt means LINE accepted the message, not that a
recipient read it. AWS schedules have minute-level precision; failures and
retries can delay execution. This design prioritizes avoiding duplicate personal
messages and therefore cannot guarantee delivery after every ambiguous failure.

## Security boundaries

The Site must remain owner-private. Its authenticated, same-origin server route
holds SENDER_TOKEN; it never sends this token or AWS credentials to the browser.
The endpoint uses constant-time bearer validation and does not enable CORS.
The scheduler execution role can invoke only the sender. The API role has no
access to the session table or encryption key. The sender has only scoped
table, logging, and failure-queue permissions. No permanent AWS access key is
deployed. AWS role credentials are excluded from the Go child environment.

The session encryption key is stored in Lambda's encrypted environment. CloudFormation
parameters use NoEcho. Principals allowed to read that environment AND the
session table can recover the session; treat deployment administrators as trusted.
Do not print configuration, payloads, message bodies, QR challenges, or raw
protocol errors. Public source contains no deployment identifiers or credentials.

The Windows migration helper reads DPAPI under the CLI process lock, encrypts
in memory, and disables the local CLI copy before handing off ciphertext. This
prevents two stores from independently refreshing the same login or reserving
conflicting request sequences. It does not sign out the phone's LINE app.
An encrypted recovery blob is kept in ignored .local/migration.enc; the key is
not stored with it. Do not restore an old session snapshot after cloud activity.

## Build and deployment

Use Go 1.27.3, Python 3.12+, AWS CLI v2, and a temporary authenticated AWS profile
named line-scheduler in ap-southeast-1. Use an IAM deployment identity for routine
maintenance. Initial account bootstrap may require its account owner. The runtime
uses scoped service roles and does not depend on the deployment login.

From the repository root:

    mkdir -p deploy/aws/.local
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o deploy/aws/.local/cloudline ./cmd/cloudline
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o deploy/aws/.local/cloudline.exe ./cmd/cloudline
    cd deploy/aws
    python3 deploy.py deploy
    python3 deploy.py status

The helper creates a private S3 artifact bucket and the line-scheduler
CloudFormation stack. Build artifacts, account-specific deployment state and
recovery data stay in .local, which is ignored. Request JSON containing secrets
uses a Linux memory-backed file descriptor, not command arguments or disk.
Artifact-bucket state is scoped to the authenticated account and region. A legacy
deployment.json is reused only when its bucket belongs to the current account.

Before loading a real account, run:

    python3 deploy.py probe

This uses synthetic credentials and proves encrypted saves and restoration across
separate Go processes inside Lambda. It refuses to replace an existing session.

Only after synthetic tests pass and account migration is authorized:

    python3 deploy.py migrate
    python3 deploy.py check
    python3 deploy.py verify

Migration runs the Windows adapter from WSL and uses the current Windows user's
saved DPAPI session. It refuses to overwrite an existing cloud session. Verify
requires restoring encryption material in a fresh process. A future account
reconnection requires a deliberate, locked replacement procedure; it is not an
automatic browser login flow.

Configure the private Site's runtime secrets through its hosting tools:

- SENDER_URL: this stack's function URL.
- SENDER_TOKEN: the API Lambda's BRIDGE_TOKEN; secret, server-only.
- SENDER_PAUSED_REASON: optional operational notice that disables the Site API.

Do not put these values in Git, frontend bundles, or hosting.json. Deploy the Site
after changing runtime settings. Keep the Site private.

## Validation

    go test -race ./cmd/cloudline ./internal/session ./internal/messaging
    go vet ./cmd/cloudline
    python3 -m unittest discover -s deploy/aws -p 'test_*.py'
    python3 -m unittest discover -s deploy/aws-probe -p 'test_*.py'

Synthetic tests cover tampered ciphertext, wrong keys, duplicate invocation,
cancellation, early/stale jobs, claim-before-send, uncertain outcomes, authorization,
and IAM isolation. Normal CI never accesses a personal LINE session.

Deployment validation confirmed a scheduled dummy receipt, duplicate suppression,
encrypted cloud state restoration, and authorized immediate and delayed encrypted
sends through the private browser interface. The delayed test was accepted 11 seconds
after its scheduled time. Both receipts remained visible after reopening the Site.
Unauthenticated requests were rejected, and the sender token was absent from the
browser build. These checks verify the tested flow, not a guarantee of future delivery.
Account-specific notices, identifiers and test recipients stay outside public source.

## Operations and recovery

If the Site cannot reach AWS, preserve the draft and inspect the account status.
If AWS suspends the account, follow its verification process; changing code or
creating new accounts is not a recovery strategy. Keep SENDER_PAUSED_REASON set
until access and saved-state restoration are verified.

On recovery, inspect existing jobs and receipts before submitting anything again.
A sending/unknown result must be checked in LINE. Never reset it to queued.
Jobs older than 15 minutes are rejected by the worker. A scheduled row can be
cancelled before delivery starts; the database state remains authoritative even
if deleting the underlying AWS schedule fails.

The failure queue is retained for 14 days. Inspect failed invocation metadata,
without logging message bodies or session content. Reserve administrative access
for maintenance and sign out the temporary deployment CLI when finished.

## Cost and teardown

There is no always-on compute, NAT gateway, paid Secrets Manager secret, or
customer-managed KMS key. Lambda, EventBridge Scheduler, provisioned DynamoDB,
SQS, CloudWatch logs and S3 are used. Light personal use is intended to fit
applicable recurring allowances; credits, account eligibility, shared limits,
storage and transfer affect the actual bill. Zero cost is not guaranteed.
The Free account plan and promotional credits expire; recurring service
allowances are separate.

For teardown, cancel pending schedules, remove schedules in this stack's group,
then delete the CloudFormation stack. Jobs and Sessions tables deliberately use
Retain, so deleting the stack does not silently erase data. Review and remove
retained tables and the artifact bucket explicitly when their data is no longer
needed. Deleting the encryption key/environment before planning session recovery
can make the retained ciphertext unusable.
