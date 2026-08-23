# AegisCloud v3 — Adversary-Informed Zero Trust Security Platform
## Complete Implementation Guide

> **v3 changelog**: this revision fixes a real platform blocker discovered while
> implementing v2 — AWS Verified Access endpoints require an ACM certificate matching the
> application domain, and the earlier guide's placeholder `.internal` domain had no
> certificate behind it at all, so the endpoint resource could never actually be created.
> **The fix does not require purchasing a domain or a Route 53 hosted zone.** ACM's
> domain-ownership validation only applies when you *request* a certificate; it does not
> apply when you *import* one you generated yourself. `terraform/verified-access` now
> generates a self-signed certificate with Terraform's `tls` provider and imports it into
> ACM — a configuration AWS's own Verified Access documentation explicitly supports
> ("HTTPS load balancers can use either self-signed or public TLS certificates"). See
> `docs/verified-access-no-domain-fix.md` for the full explanation and how to reach/test
> the endpoint. Everything else from v2 (Phases 1-3, 5-14) is unaffected and unchanged —
> only Phase 4 (Verified Access) and its optional Phase 13 variant were touched by this fix.

This is the complexity upgrade to the single-account AegisCloud build. Everything from the
previous version (foundation, guardrails, identity, Verified Access, detection/remediation,
Wazuh) is preserved and included here so this package is standalone — you don't need the
older zip. On top of that base, five new phases turn this from "I configured a set of AWS
security services" into "I built a platform, then proved it works by attacking it, gated
every change through policy-as-code, and extended AWS's native tooling with custom
detections."

**This is the resume-defining difference.** The original scope reads as SSE/Zero Trust
implementation work — valuable, but it looks like configuring products. This version adds
detection engineering, adversary emulation, DevSecOps pipeline security, and application/
container security — the breadth that keeps you from being typecast as a single-vendor
product engineer.

---

## Picking Up From Where You Are

You've told me your current state, so here's exactly where to resume:

- ✅ Terraform and AWS CLI installed
- ✅ Entra ID tenant integrated with AWS IAM Identity Center
- 🔄 SCIM provisioning in progress

**Don't redo any of this.** Finish the SCIM provisioning (assign your `SecurityEngineers`
group in the Entra Enterprise Application's Provisioning tab, confirm it syncs — check
IAM Identity Center console → Groups to see the group appear), then start at **Phase 1**
below for the foundation Terraform. Phase 3 (Identity Federation) in this guide is written
to match what you've already done — just apply the Terraform permission sets once SCIM
finishes syncing, you don't need to redo the SAML/SCIM configuration steps themselves.

---

## What's New in v2 — And Why Each Piece Changes Your Resume Story

| New phase | What it adds | Why it matters for "not just a product engineer" |
|---|---|---|
| **9. GuardDuty** | Real behavioral/ML threat detection, distinct from Config's compliance checks | Shows you understand the difference between compliance checking and threat detection — two different disciplines |
| **10. Adversary Emulation** | Stratus Red Team attacks against your own account, mapped to MITRE ATT&CK, producing a Navigator coverage layer | This is detection engineering / purple teaming — a meaningfully more advanced skill set than implementation work, and the single strongest differentiator in this package |
| **11. Policy-as-Code Gate** | Checkov + OPA/Conftest blocking insecure Terraform at PR time | DevSecOps / shift-left security — CI/CD pipeline security engineering, not just "I used GitHub Actions" |
| **12. IAM Attack-Path Analysis** | Cloudsplaining scans + custom ASFF findings pushed into Security Hub via Lambda | Shows you can extend AWS's native tooling with custom detections, not just consume managed rules |
| **13. Containerized Workload** | ECS Fargate, ECR with scan-on-push, task-level IAM, hardened non-root container | Adds application/container security — a distinct discipline from network and identity security |
| **(v3 fix) Self-Signed Cert for Verified Access** | Terraform-generated self-signed cert imported into ACM, unblocking the Verified Access endpoint with zero domain purchase | Shows you understood *why* the platform requirement exists and solved it correctly (import vs. request) rather than reaching for the expensive/inconvenient default fix |

---

## Architecture Overview

```
                    ┌────────────────────────────────────────────────────────┐
                    │                  Single AWS Account                       │
                    │                                                            │
                    │  Identity: Entra ID --SAML/SCIM--> IAM Identity Center     │
                    │  Guardrails: IAM Permission Boundaries (SCP replacement)   │
                    │                                                            │
                    │  ┌──────────────┐ ┌───────────────┐ ┌──────────────┐      │
                    │  │ Security     │ │ Workloads      │ │ Shared        │      │
                    │  │ Tools tier   │ │ tier           │ │ Services tier │      │
                    │  │              │ │                │ │               │      │
                    │  │ - Config     │ │ - ECS Fargate  │ │ - Identity    │      │
                    │  │ - SecHub     │ │   (containers) │ │   Center      │      │
                    │  │ - GuardDuty  │ │ - Verified     │ │               │      │
                    │  │ - Remediation│ │   Access       │ │               │      │
                    │  │   Lambdas    │ │   endpoint     │ │               │      │
                    │  │ - Enrichment │ │ - Internal ALB │ │               │      │
                    │  │   Lambda     │ │                │ │               │      │
                    │  └──────────────┘ └───────────────┘ └──────────────┘      │
                    └──────────────────────────┬─────────────────────────────────┘
                                                 │
                        ┌────────────────────────┼───────────────────────┐
                        │                         │                        │
                Findings -> S3               Findings <- Cloudsplaining   Adversary
                (Wazuh pulls,                 (weekly CI scan -> S3 ->     emulation
                 Phase 8)                     Lambda -> Security Hub,      (Stratus Red
                        │                     Phase 12)                    Team, Phase 10)
                        ▼                                                        │
                ┌──────────────┐                                                 ▼
                │ Wazuh Manager │                                    ATT&CK Navigator
                │ (VirtualBox)  │                                    coverage layer
                └──────────────┘

CI/CD: every PR -> Policy-as-Code Gate (Checkov + OPA, Phase 11) -> must pass ->
       Terraform Deploy (Phase 6, unchanged) -> Drift Detection (daily, unchanged)
```

---

## Prerequisites (in addition to what you already have)

1. **Stratus Red Team CLI** — for Phase 10:
   ```bash
   brew install datadog/stratus-red-team/stratus-red-team
   ```
   or download a release binary from
   [github.com/DataDog/stratus-red-team/releases](https://github.com/DataDog/stratus-red-team/releases)
2. **Cloudsplaining** — for Phase 12: `pip install cloudsplaining`
3. **Checkov** — for Phase 11: `pip install checkov`
4. **Conftest** — for Phase 11: see install command in `policy-as-code/checkov-config.yaml`
   comments, or [conftest.dev](https://www.conftest.dev/install/)
5. **Docker** — for Phase 13, to build the demo container image
6. **A free AbuseIPDB API key** — for Phase 14 (threat intel enrichment):
   [abuseipdb.com/api](https://www.abuseipdb.com/api)

---

## Phase 1-8 — Foundation Through Wazuh (Unchanged, See Below for Quick Reference)

These phases are identical to the single-account design you already have a guide for.
Full Terraform is included in this package (`terraform/foundation`, `terraform/guardrails`,
`terraform/identity-center`, `terraform/verified-access`, `terraform/detection-remediation`,
`terraform/wazuh-integration`). Quick summary of what each does and the apply order:

1. **Foundation** — one VPC, three subnet tiers (security-tools, workloads, shared-services),
   NACLs, GitHub Actions OIDC role. `cd terraform/foundation && terraform init && terraform apply`
2. **Guardrails** — the IAM Permission Boundary replacing SCPs. `cd terraform/guardrails && terraform apply`
3. **Identity Center** — permission sets + account assignment (you're already most of the way
   here — just apply once SCIM sync is confirmed). `cd terraform/identity-center && terraform apply`
4. **Verified Access** — ZTNA control plane for the demo app. `cd terraform/verified-access && terraform apply`
   **v3 change**: this module now generates and imports a self-signed certificate
   automatically as part of `terraform apply` — no domain purchase, no Route 53 hosted
   zone, no extra manual step required before applying. See
   `docs/verified-access-no-domain-fix.md` for why this works and how to actually reach
   the endpoint to test/screenshot it (you'll add one line to your local hosts file,
   nothing more).
5. **Detection & Remediation** — Config, Security Hub (CIS + NIST), the two remediation
   Lambdas. `cd terraform/detection-remediation && terraform apply`
6. **CI/CD** — already wired via the OIDC role from Phase 1; workflows in `github-actions/`.
7. **Compliance mapping** — automatic once Phase 5's Security Hub standards subscriptions are applied.
8. **Wazuh integration** — findings export to S3, pulled by your VirtualBox Wazuh manager.
   `cd terraform/wazuh-integration && terraform apply`, then follow
   `docs/wazuh-virtualbox-setup.md`.

If you want the fully detailed, step-by-step version of these 8 phases (exact console
click-paths for the Entra/Identity Center SAML setup, testing procedures for each phase,
etc.), that's in the previous guide — everything here is the working code, this README
focuses its depth on what's NEW.

---

## The Verified Access Fix, In Brief (full detail in `docs/verified-access-no-domain-fix.md`)

**The problem**: AWS Verified Access endpoints require a `domain_certificate_arn` — an ACM
certificate whose domain matches the endpoint's `application_domain`. Normally you'd get
that certificate by having ACM *request* one, which requires DNS-validating that you own
the domain — meaning you'd need to actually own a domain.

**The fix — no purchase required**: ACM's domain-ownership check only applies to
*requesting* a certificate. *Importing* a certificate you already hold the private key for
skips that check entirely, because there's no issuing CA to validate against. AWS's own
Verified Access docs confirm self-signed certificates are explicitly supported. So
`terraform/verified-access/main.tf` now generates a self-signed cert with Terraform's `tls`
provider and imports it into ACM automatically — zero manual steps, zero domain purchase,
zero ongoing cost beyond what you were already paying for the Verified Access instance
itself.

**Reaching it to test**: your Verified Access endpoint gets a real, AWS-generated, publicly
resolvable DNS name automatically — that's inherent to the product. Resolve that name to
an IP once, add one line to your local hosts file mapping your made-up `application_domain`
to that IP, and the Entra ID → policy evaluation → app access flow works completely
end-to-end, with a certificate warning in the browser that's honest evidence of the
constraint you solved around (not something to hide in your portfolio writeup).

Full walkthrough, including the exact commands and an optional step to suppress the browser
warning for cleaner screenshots, is in `docs/verified-access-no-domain-fix.md`.

---

## Phase 9 — GuardDuty: Real Threat Detection

### What you're building
Amazon GuardDuty, which is fundamentally different from everything in Phase 5: Config
rules are deterministic ("is this setting compliant, yes/no"). GuardDuty profiles what's
*normal* for your account — API call patterns, network flows, DNS queries — and flags
deviations: credential exfiltration, cryptomining, command-and-control communication,
reconnaissance. This is the detection source Phase 10's adversary emulation actually tests
against.

### Steps

1. Apply the module:
   ```bash
   cd terraform/guardduty
   terraform init
   terraform apply
   ```
2. GuardDuty findings flow into Security Hub **automatically** — no extra wiring — because
   both services integrate natively once enabled. This means they also flow through your
   existing Phase 8 export-to-S3 pipeline to Wazuh, for free.
3. **Test it**: GuardDuty has a built-in sample-findings generator for exactly this purpose:
   ```bash
   aws guardduty create-sample-findings --detector-id <your-detector-id> \
     --finding-types Backdoor:EC2/C&CActivity.B!DNS UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
   ```
   Confirm these appear in both the GuardDuty console and Security Hub within a couple
   minutes.

---

## Phase 10 — Adversary Emulation (Stratus Red Team + MITRE ATT&CK)

### What you're building
This is the centerpiece of the whole upgrade. You will run real attack techniques against
your own AWS account using Stratus Red Team, then manually verify what your detections
(GuardDuty, Security Hub, Config, the remediation Lambdas) actually caught — and produce a
visual MITRE ATT&CK Navigator layer showing your coverage.

**Read this before running anything**: Stratus Red Team executes *real* AWS API calls, not
simulations. Only run this against the AegisCloud account you own and control. Never run
it against shared, production, or employer infrastructure.

### Steps

1. Review `scripts/run-stratus-attacks.sh` — it runs four techniques chosen specifically
   because they map to detections already built in this project:
   - `aws.credential-access.ec2-instance-credentials` — tests the IMDSv2 permission boundary
   - `aws.exfiltration.s3-backdoor-bucket-policy` — tests GuardDuty + the S3 remediation Lambda
   - `aws.persistence.iam-backdoor-role` — tests whether Cloudsplaining (Phase 12) catches
     a backdoor IAM trust relationship
   - `aws.defense-evasion.cloudtrail-stop` — tests (and, honestly, is likely to **fail to
     detect**) an attacker disabling your audit trail — see the note below on why this is
     left as an intentional, documented gap rather than something to feel you must fix
     before you can talk about this project

2. Run it:
   ```bash
   chmod +x scripts/run-stratus-attacks.sh
   ./scripts/run-stratus-attacks.sh
   ```
   This warms up, detonates, waits for the detection pipeline to process, and cleans up
   after each technique — real attack, then real cleanup, nothing left behind.

3. **Manually verify each technique's result** — check the GuardDuty console, Security Hub
   console, and CloudWatch Logs for the remediation Lambdas, all filtered to the time
   window of your run. This manual verification step is deliberate: it's what makes your
   eventual claim "I validated my detections" true rather than assumed.

4. **Record your real findings** in `docs/attack-coverage-data.json` — it's pre-populated
   with placeholder/example entries and clear instructions on what to fill in after your
   actual run. Be honest here — a documented gap is more valuable to your portfolio than a
   fabricated clean sweep, both ethically and because "gap + here's what I'd add to close
   it" is a stronger interview answer than "everything worked perfectly."

5. **Generate the Navigator layer**:
   ```bash
   python3 scripts/generate-attack-navigator-layer.py
   ```
   This produces `aegiscloud-attack-navigator-layer.json`. Upload it at
   [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
   (Open Existing Layer → Upload from Local) to see your coverage map rendered visually,
   color-coded green (prevented) / yellow (detected) / red (gap). **Screenshot this for
   your portfolio** — it's genuinely one of the strongest single artifacts you can show.

### On the CloudTrail-stop gap specifically

This project, as built, most likely will **not** detect `aws.defense-evasion.cloudtrail-stop`
in real time. That's a true, useful thing to know and say out loud rather than hide — the
honest fix is a Config rule (`cloudtrail-enabled`) plus an EventBridge rule watching for the
`StopLogging` API call directly, which you can note as a documented next step. Knowing the
gap and the fix is a stronger signal than not having looked for gaps at all.

---

## Phase 11 — Policy-as-Code CI/CD Gate

### What you're building
Every Terraform change gets scanned by Checkov (known misconfiguration patterns) and
Conftest/OPA (custom policies evaluated against the actual plan JSON) *before* it can
merge — insecure infrastructure gets rejected at PR review, not caught after it's already
deployed.

### Steps

1. Review the two custom OPA policies in `policy-as-code/opa/`:
   - `no_public_s3.rego` — denies any planned S3 ACL/security-group change that would open
     things up publicly (a second, independent layer beyond the runtime guardrails)
   - `require_permission_boundary.rego` — denies any new IAM role/user that doesn't set
     `permissions_boundary` — this is a self-referential check: it enforces that the
     single-account guardrail model from Phase 2 can't accidentally be bypassed by a future
     PR that forgets to attach it

2. Add `github-actions/policy-gate.yml` to `.github/workflows/` in your repo.

3. **Set up branch protection** on `main` in your GitHub repo settings: require the
   "Policy-as-Code Gate" status check to pass before merging is allowed. This is the actual
   enforcement mechanism — without branch protection, the workflow running is just
   informational, not a gate.

4. **Test it**: open a PR that introduces a deliberately non-compliant change (e.g., an S3
   bucket ACL set to `public-read`, or a new IAM role without a permission boundary) —
   confirm the PR is blocked with a clear failure message naming the violated policy.

---

## Phase 12 — IAM Attack-Path Analysis (Cloudsplaining)

### What you're building
Config and Security Hub's managed rules check individual settings in isolation.
Cloudsplaining analyzes IAM policy *graphs* — it catches privilege-escalation paths that
exist because of how several individually-reasonable permissions combine, which no
single-setting check can see. Findings get converted into proper ASFF (AWS Security Finding
Format) and pushed into Security Hub, so they live in the same dashboard as everything else.

### Steps

1. Apply the module:
   ```bash
   cd terraform/iam-attack-path
   terraform init
   terraform apply
   ```
2. Attach the `iam_scan_and_upload_policy_arn` output to your GitHub Actions OIDC role
   (add it as an `aws_iam_role_policy_attachment` in `terraform/foundation/oidc.tf`,
   referencing this module's output — or simplest for a portfolio project, run the scan
   manually the first time to test before wiring full CI automation).
3. Add `github-actions/iam-risk-scan.yml` to `.github/workflows/` — runs weekly, uploads
   the Cloudsplaining report to S3, which triggers the ingestion Lambda automatically.
4. **Test manually first**:
   ```bash
   pip install cloudsplaining
   aws iam get-account-authorization-details > auth-details.json
   cloudsplaining scan --input-file auth-details.json --output json > report.json
   aws s3 cp report.json s3://aegiscloud-cloudsplaining-reports-<your-account-id>/reports/test-run.json
   ```
   Within a minute, check Security Hub for new findings with generator ID
   `aegiscloud-cloudsplaining-iam-risk-scan`.

---

## Phase 13 — Containerized Workload (ECS Fargate)

### What you're building
Replacing (or supplementing) the static EC2 demo app with a real containerized workload —
ECR with scan-on-push image scanning, ECS Fargate (no EC2 instances to patch, no SSH
surface), task-level IAM instead of instance-level, and a hardened non-root,
read-only-filesystem container, fronted by an internal ALB.

### Steps

1. Build and push the demo container — see `docs/demo-app-dockerfile` for the full
   Dockerfile plus the minimal `app.py` it expects, and the exact build/push commands.

2. Apply the module:
   ```bash
   cd terraform/containerized-workload
   terraform init
   terraform apply
   ```

3. **Point Verified Access at the new ALB instead of (or alongside) the EC2 demo app** —
   update `terraform/verified-access/main.tf`'s endpoint to use `attachment_type = "load-balancer"`
   and reference this module's `internal_alb_arn` output instead of the EC2 network
   interface, if you want Verified Access fronting the containerized version specifically.

4. **Test**: confirm ECR shows a completed vulnerability scan on your pushed image (ECR
   console → Repositories → your image → Scan results). Confirm the ECS service reaches
   `RUNNING` state and the ALB target group shows a healthy target.

---

## Phase 14 — Threat Intel Enrichment

### What you're building
High-severity GuardDuty findings (severity ≥ 7) get automatically enriched with AbuseIPDB
threat intelligence — abuse confidence score, report count, Tor exit-node status — before
being pushed as a cross-referenced custom finding into Security Hub. An analyst sees "this
IP has a 92% abuse confidence score with 340 reports" instead of a bare IP address.

### Steps

1. Get a free AbuseIPDB API key at [abuseipdb.com/api](https://www.abuseipdb.com/api)
   (1,000 requests/day free tier).
2. Apply the module (needs the GuardDuty rule outputs from Phase 9):
   ```bash
   cd terraform/threat-intel-enrichment
   terraform init
   terraform apply -var="abuseipdb_api_key=<your-key>" \
     -var="guardduty_high_severity_rule_arn=<output from guardduty module>"
   ```
3. **Test**: use the same `aws guardduty create-sample-findings` command from Phase 9 with
   a finding type that includes a remote IP (e.g.,
   `UnauthorizedAccess:EC2/SSHBruteForce`), and confirm an enriched finding with generator ID
   `aegiscloud-threat-intel-enrichment` appears in Security Hub shortly after.

---

## Final Validation Checklist

- [ ] GuardDuty enabled, sample findings appear in both GuardDuty console and Security Hub
- [ ] Stratus Red Team run completed, results recorded honestly in `attack-coverage-data.json`
- [ ] ATT&CK Navigator layer generated and viewable at mitre-attack.github.io/attack-navigator
- [ ] A deliberately non-compliant PR is blocked by the Policy-as-Code Gate
- [ ] Cloudsplaining findings appear in Security Hub with the correct generator ID
- [ ] ECR shows a completed image scan; ECS service is RUNNING with a healthy ALB target
- [ ] A high-severity GuardDuty sample finding produces an enriched AbuseIPDB finding in Security Hub
- [ ] Everything from Phases 1-8 still validates as it did in the single-account guide

## Cost & Cleanup

This version costs more to run than the single-account base — GuardDuty, ECS Fargate, the
ALB, and NAT gateway all add up. Budget **$25-45/month** if left running continuously;
tear down aggressively between working sessions:

```bash
cd terraform/threat-intel-enrichment && terraform destroy
cd ../iam-attack-path && terraform destroy
cd ../containerized-workload && terraform destroy
cd ../guardduty && terraform destroy
cd ../wazuh-integration && terraform destroy
cd ../detection-remediation && terraform destroy
cd ../verified-access && terraform destroy
cd ../identity-center && terraform destroy
cd ../guardrails && terraform destroy
cd ../foundation && terraform destroy
```
