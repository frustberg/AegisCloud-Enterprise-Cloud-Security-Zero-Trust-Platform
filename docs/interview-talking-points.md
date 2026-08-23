# AegisCloud v3 — Interview Talking Points

## The 30-second version

"I built a single-account AWS security platform, then adversary-emulated against my own
detections using Stratus Red Team, mapped the results to MITRE ATT&CK in a Navigator
coverage layer, gated every infrastructure change through a Checkov + OPA policy pipeline,
extended Security Hub with custom findings from an IAM attack-path scanner and threat-intel
enrichment, and containerized the workload with image scanning and task-level IAM. It's
identity, network, detection, container, and pipeline security in one project, not just one
vendor's console."

## "Tell me about a roadblock you hit and how you solved it"

This is a genuinely strong answer — use it:

> "When I got to publishing the Verified Access endpoint, Terraform failed — AWS Verified
> Access requires an ACM certificate matching the application's domain, and I'd been using
> a placeholder internal domain with no certificate behind it at all. I diagnosed it
> precisely: this wasn't a Terraform bug, a SAML misconfiguration, or an Identity Center
> issue — every other component (trust provider, instance, group, policy model, SCIM
> provisioning) was working correctly. It was a hard AWS platform requirement I hadn't
> accounted for. I looked at the standard fix — register a domain and get a
> publicly-validated certificate — and decided that wasn't the right trade-off for a
> portfolio project. Instead I looked at what the requirement actually enforces: a valid
> ACM certificate ARN whose CN matches the domain. ACM's domain-ownership validation only
> applies when you *request* a certificate from a CA — it doesn't apply when you *import*
> one you already hold the private key for. So I generated a self-signed certificate with
> Terraform's own `tls` provider and imported it into ACM, which AWS's Verified Access
> documentation explicitly supports. Zero cost, zero domain purchase, fully reproducible
> in Terraform rather than a manual console step."

This shows: precise root-cause diagnosis (not just "it didn't work"), reading past the
default/obvious fix to understand what the underlying requirement actually checks, and
choosing a solution that's genuinely correct — not a hack — while being honest that a real
production deployment would use a properly-issued public certificate instead. If asked "why
not just buy the cheap domain," a fine honest answer is simply that you wanted to solve the
underlying technical constraint on its own terms rather than spend around it.

## "What's the most interesting thing you found?"

Have a real answer ready from `docs/attack-coverage-data.json` once you've actually run the
emulation — the strongest version of this answer names a genuine gap you found (e.g., "my
setup didn't detect CloudTrail being disabled in real time — only a periodic IAM scan would
have caught the backdoor role afterward") and explains what you'd add to close it. Finding
and naming a real gap is more credible than claiming full coverage.

## "Why add adversary emulation instead of just more detections?"

> "Anyone can configure GuardDuty and Config rules and claim 'this environment is
> monitored.' The only way to know whether detections actually work is to attack the
> environment the way a real adversary would and watch what fires. Stratus Red Team runs
> real AWS API calls — not simulated — so this validates against reality, not against my
> assumptions about how GuardDuty behaves."

## "Walk me through the policy-as-code gate"

> "Checkov scans the Terraform source for known misconfiguration patterns. Separately,
> Conftest evaluates OPA policies against the actual `terraform plan` JSON output — that
> catches things a pure source scan can miss, like a variable-driven resource that only
> becomes insecure under specific input combinations. One of my OPA policies is
> self-referential: it fails the build if any new IAM role doesn't have the project's
> permission boundary attached, which enforces the single-account guardrail model I built
> in Phase 2 at the pipeline level, not just at apply time."

## "Why IAM attack-path analysis on top of Config/Security Hub?"

> "Config and Security Hub's managed rules check individual settings in isolation — is
> this bucket public, yes or no. Cloudsplaining analyzes policy GRAPHS: it catches
> privilege escalation paths that exist because of how several individually-fine
> permissions combine, which no single-setting check can see. I wrote a Lambda that
> converts Cloudsplaining's JSON output into proper ASFF findings and pushes them into
> Security Hub via BatchImportFindings, so this shows up in the same dashboard as
> everything else instead of living only as a CI artifact nobody opens again."

## "Why containerize part of this?"

> "The rest of the project is identity and network security — Zero Trust access, IAM
> guardrails, threat detection. None of that touches application/container security, which
> is its own discipline: image scanning, task-level IAM instead of instance-level, avoiding
> a shared credential surface across workloads. Adding ECS Fargate with ECR scan-on-push
> and a non-root, read-only-filesystem container was specifically to cover that gap rather
> than have the whole project be one flavor of security."

## "What would you do with more time / in a real job?"

- Close the CloudTrail-disable detection gap found during emulation (Config rule +
  EventBridge rule on the `StopLogging` API call).
- Move the Cloudsplaining scan from weekly-scheduled to triggered on every Terraform apply.
- Replace the IAM user + access key in the Wazuh integration with IAM Roles Anywhere.
- Expand adversary emulation to a broader Stratus Red Team technique set covering more
  ATT&CK tactics (currently covers Credential Access, Exfiltration, Persistence, Defense
  Evasion — Discovery and Lateral Movement aren't yet represented).
- Add SBOM generation (e.g., Syft) to the container build pipeline alongside the existing
  Inspector image scanning, for full supply-chain visibility.

## Numbers worth having ready (fill in from your real run)

- ATT&CK techniques emulated: 4 (Credential Access, Exfiltration, Persistence, Defense Evasion)
- Techniques prevented outright vs. detected vs. gap: ___ / ___ / ___
- Time from misconfiguration to auto-remediation: ___ seconds
- CIS AWS Foundations Benchmark compliance score: ___%
- Cloudsplaining findings identified and remediated: ___
