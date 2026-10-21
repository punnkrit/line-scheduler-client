# AWS scheduling probe

An isolated dummy test of EventBridge Scheduler invoking Lambda and writing a
durable DynamoDB receipt. This does **not** deploy the Go LINE client, store its
session, send messages, or prove LINE compatibility with Lambda. Python keeps
this first infrastructure test small and independent of the sender.

## Account and access

Use an existing AWS account and a temporary CLI login, preferably through a
non-root administrative identity. Do not create or paste long-lived access keys.
AWS CLI 2.32 or newer supports browser sign-in:

```sh
aws login --profile line-scheduler --region ap-southeast-1 --remote
```

An IAM user or role needs `SignInLocalDevelopmentAccess` for this flow as well as
the deployment permissions. Identity Center accounts should use `aws configure
sso` and `aws sso login` instead. All probe commands explicitly select a named
profile and region; Singapore is the default and can be changed with `--region`.

The deploying identity needs CloudFormation, Lambda, DynamoDB, CloudWatch Logs,
SQS, Scheduler and IAM role/policy creation/pass-role permissions for this
isolated stack. The deployed runtime roles have narrowly scoped permissions.
The probe creates no public endpoint or IAM access key.

## Local validation

From this directory, without AWS credentials:

```sh
python3 -m unittest -v
python3 template.py > /tmp/line-scheduler-dummy-template.json
```

Tests cover early execution, concurrent duplicates, conflicting IDs, malformed
inputs and storage errors. An atomic receipt write only proves idempotence for
this dummy database operation; a LINE send has an external side effect and will
need a separate unknown-outcome reconciliation design.

## Deploy and exercise

```sh
python3 probe.py deploy
aws --profile line-scheduler --region ap-southeast-1 cloudformation describe-stacks \
  --stack-name line-scheduler-dummy-probe
```

Wait for `CREATE_COMPLETE`. The deploy command refuses to overwrite an existing
stack. It validates the template with AWS before creating it. Then:

```sh
python3 probe.py schedule --minutes 2
python3 probe.py status PROBE_JOB_ID_FROM_SCHEDULE
python3 probe.py duplicate PROBE_JOB_ID_FROM_SCHEDULE
python3 probe.py failures
```

Only `schedule` arms an invocation. It creates a one-time schedule with its
flexible window disabled, and asks AWS to delete it when complete. Its saved
`.local/` request contains synthetic metadata, not secrets. If creation times
out, inspect that named schedule and reuse the saved request/client token rather
than running `schedule` again and accidentally creating a second test.

The receipt records UTC due/completion times and measured delay. Polling status
does not execute the job. A future job is rejected without a successful receipt;
AWS retries may then deliver it after it is due. Completed receipts survive cold
starts because DynamoDB, not Lambda's temporary filesystem, stores them.
Duplicate invocations preserve the first receipt. Both scheduler delivery failures
and exhausted Lambda asynchronous errors go to the encrypted failure queue.

AWS documents 60-second scheduler precision, not exact-second delivery. Cold starts,
throttling and retries can add delay. A missing receipt is pending **or failed**,
never proof of success. No claim about physical PC power state is necessary.

## Cost and cleanup

There is no VM, NAT gateway, load balancer, provisioned Lambda concurrency,
customer-managed KMS key, API Gateway or paid Secrets Manager secret. The small
Lambda workload and single provisioned DynamoDB read/write capacity unit are
intended to fit applicable recurring free allowances. Logs and SQS have separate
pricing. Existing account usage shares allowances, so a zero bill is not guaranteed.
Logs expire after seven days and failure messages after fourteen days.

This is a disposable probe. Deleting its CloudFormation stack also deletes its
synthetic receipts and failure queue. Ensure no pending test is still needed,
then use the AWS console to delete `line-scheduler-dummy-probe`. There is no
production data to migrate from it. Finite one-time schedules are not a recurring
background expense.

## Next stage

Before real LINE use: package the Go runtime, implement protected durable session
storage and atomic sequence updates, serialize per-account operations, and test
refresh, restarts, partial failures and ambiguous send results with synthetic data.
The current systemd-based headless storage is not directly usable in Lambda.
Never blindly retry a LINE mutation just because a Lambda invocation failed.
Sites remains the planned compose/schedule interface; no AWS secret belongs in
browser JavaScript. Use the requested frontend-design skill for the actual UI.

Sources: [CLI sign-in](https://docs.aws.amazon.com/signin/latest/userguide/command-line-sign-in.html),
[scheduler timing](https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html),
[Lambda retries](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html),
[scheduler role trust](https://docs.aws.amazon.com/scheduler/latest/UserGuide/cross-service-confused-deputy-prevention.html).
