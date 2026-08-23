# AWS Verified Access Without an Owned Domain

## The blocker, precisely

AWS Verified Access requires every endpoint to present a TLS certificate whose Common Name
matches the domain your users will type/browse to. Normally you'd get that certificate by
having ACM **request** one — which means proving you control the domain via DNS or email
validation, which means owning a domain and (usually) a Route 53 hosted zone for it.

## The fix, precisely

ACM's domain-ownership validation is a property of **requesting** a certificate, not a
property of **holding** one. ACM also supports **importing** a certificate you generate
yourself — a self-signed certificate, where you are your own issuing authority. Import
skips domain validation entirely, because there's no CA involved to validate anything
against. AWS's own Verified Access documentation confirms self-signed certificates are
explicitly supported for exactly this reason: *"HTTPS load balancers can use either
self-signed or public TLS certificates."*

`terraform/verified-access/main.tf` in this package now:
1. Generates an RSA key pair and a self-signed X.509 certificate using Terraform's `tls`
   provider — no OpenSSL commands to run by hand, no files to manage outside state.
2. Imports that certificate into ACM via `aws_acm_certificate` (using `private_key` +
   `certificate_body`, which is the **import** code path, not the `domain_validation_options`
   **request** code path).
3. Uses the resulting ACM certificate ARN as the Verified Access endpoint's
   `domain_certificate_arn`, and a made-up domain name (`demo-app.aegiscloud.local` by
   default) as `application_domain`.

This is not a hack that happens to work — it's a documented, supported AWS configuration.
The only thing you lose versus a publicly-issued certificate is that your browser will show
a "certificate not trusted" warning unless you explicitly trust your self-signed cert (or
click through the warning) — which is a client-side cosmetic issue, not a deployment
limitation, and doesn't affect whether the underlying Zero Trust access control (identity
federation, policy evaluation, device posture check) actually works.

---

## Reaching and testing the endpoint

Your `application_domain` (e.g., `demo-app.aegiscloud.local`) is not publicly resolvable —
it's made up. But your **Verified Access endpoint itself** gets a real, AWS-generated,
publicly-resolvable DNS name automatically (this is the `verified_access_endpoint_dns`
Terraform output) — that's inherent to how Verified Access works; it's meant to be reachable
from anywhere, not just inside your VPC, which is the whole point of a ZTNA product.

### Steps

1. **Apply the module and get the real endpoint DNS name**:
   ```bash
   cd terraform/verified-access
   terraform init
   terraform apply
   terraform output verified_access_endpoint_dns
   ```
   This gives you something like
   `demo-app-1234567890abcdef.vai-0a1b2c3d4e5f6789.prod.verified-access.us-east-1.amazonaws.com`
   (exact format varies).

2. **Resolve that name to an IP address**:
   ```bash
   nslookup demo-app-1234567890abcdef.vai-....amazonaws.com
   ```
   Note the IP(s) returned.

3. **Add a hosts file entry** mapping your made-up `application_domain` to that IP:

   **macOS/Linux** — edit `/etc/hosts` (needs `sudo`):
   ```
   203.0.113.42   demo-app.aegiscloud.local
   ```

   **Windows** — edit `C:\Windows\System32\drivers\etc\hosts` as Administrator:
   ```
   203.0.113.42   demo-app.aegiscloud.local
   ```

4. **Browse to `https://demo-app.aegiscloud.local`**. Your browser connects to the real
   Verified Access endpoint (via the IP you mapped), presents SNI for
   `demo-app.aegiscloud.local`, and Verified Access responds with your self-signed
   certificate — whose CN matches, so the connection completes past the TLS layer. You'll
   get a browser warning about the certificate not being from a trusted CA (expected —
   click through / accept it, same as you would for any self-signed cert in a lab
   environment). After that, you should be redirected to Entra ID to authenticate, then
   back to the app if your group membership and device posture satisfy the policy.

5. **This is exactly what to screenshot for your portfolio**: the Entra ID redirect,
   the successful post-auth landing on the app, and (in a separate test) an unauthenticated
   or wrong-group session being denied. The self-signed cert warning in the screenshot is
   fine to leave visible — it's honest evidence of the constraint you solved around, not
   something to hide.

### Important caveat: this IP can change

The IP behind an AWS-generated DNS name isn't guaranteed static forever (Verified Access
may sit behind infrastructure that rotates IPs). For a portfolio demo/testing session this
is a non-issue — resolve it fresh each time you sit down to test. If you wanted this to be
durable long-term without owning a domain, the next-best option (still free) is scripting
the `nslookup` + hosts-file-update step so you re-resolve it each session rather than
hardcoding a single IP permanently.

---

## What this does NOT fix, and is worth stating honestly

- Your browser will always show a certificate warning for this self-signed cert, unless you
  manually import your generated CA into your OS/browser trust store (optional, covered
  below if you want a cleaner screenshot).
- This is not how you'd do it in a real company deployment — a real deployment has an owned
  domain and a properly-issued public ACM certificate with automatic renewal. Say this
  plainly if asked; the point of this fix is portfolio feasibility, not that self-signed
  certs are how production Zero Trust deployments work.

### Optional — suppress the browser warning for cleaner screenshots

Export the self-signed certificate from Terraform state and add it to your OS/browser's
trusted root store:

```bash
terraform output -raw -state=terraform.tfstate ... # or simplest: re-derive it from the
# tls_self_signed_cert resource's cert_pem attribute via `terraform show`
```

Then import that `.pem` file into:
- **macOS**: Keychain Access → System → Certificates → drag in the file → set to "Always Trust"
- **Windows**: `certmgr.msc` → Trusted Root Certification Authorities → Import
- **Linux**: varies by distro, typically `/usr/local/share/ca-certificates/` + `update-ca-certificates`

This is optional and purely cosmetic — the Zero Trust access control itself works
identically with or without doing this.
