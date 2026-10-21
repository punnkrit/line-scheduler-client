# Private Sites interface

This directory contains the scheduler's React/Vinext interface, authenticated API
relay, and Sites build support. Deployment identity, credentials, live messages,
contact lists, and uploads are intentionally absent.

Use the Sites plugin to create a new **owner-private** Site from this directory.
The included `.openai/hosting.json` has no project ID: let Sites assign a new one.
Do not copy another deployment's ID or publish this interface publicly. The single
LINE account is protected by Sites' owner-only audience, not per-user routing.

1. Register a private Site and retain its generated HTTPS origin.
2. Deploy AWS with `python3 deploy.py deploy --site-origin https://YOUR-SITE`.
3. Configure `SENDER_URL` and `SENDER_TOKEN` as secret server runtime variables
   through Sites. Obtain them from your own stack; never put them in source.
4. Build and publish through the Sites workflow. Redeploy after runtime-secret changes.
5. Complete the separate [LINE session bootstrap](../docs/ARCHITECTURE.md#line-sign-in-step-by-step).

For local development, install the locked dependencies using the Sites dependency
helper (or `npm ci`) and run `npm run dev`. Local preview mocks ChatGPT identity;
it does **not** connect a LINE account or supply production secrets. Do not expose
the preview server publicly. `npx tsc --noEmit` checks the application types.

`app/chatgpt-auth.ts` trusts identity headers injected by Sites. Deploying these
files to a different host without a trusted authentication gateway is unsafe.
The relay restricts the sender URL to Lambda URLs in `ap-southeast-1`; changing
regions requires updating both that restriction and the S3 upload-host restriction.

Keep copy functional. No promotional hero, taglines, or decorative explanatory footers.
