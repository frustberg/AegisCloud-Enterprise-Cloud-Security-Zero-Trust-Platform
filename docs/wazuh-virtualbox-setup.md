# Wazuh on VirtualBox — Setup and AWS S3 Integration

This covers two things: getting Wazuh running on a VirtualBox VM if you haven't already,
and wiring it up to pull AegisCloud's exported findings from S3 on a schedule.

---

## Part 1 — Installing Wazuh on VirtualBox (skip if already running)

### Option A: Wazuh's pre-built OVA (fastest)

1. Download the Wazuh OVA from the [official downloads page](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html).
2. In VirtualBox: File → Import Appliance → select the downloaded `.ova` file.
3. Allocate at least **4GB RAM / 2 vCPUs** for a single-node all-in-one install (manager +
   indexer + dashboard) — this is fine for a portfolio project, don't over-provision.
4. **Network setting**: set the VM's network adapter to **NAT** (simplest — the VM gets
   outbound internet through your host machine, and this is all this integration needs) or
   **Bridged** if you want to reach the Wazuh dashboard from other devices on your home
   network. Either works for this project — you do **not** need port forwarding rules for
   the AWS integration to work, since the VM only ever makes outbound connections to AWS.
5. Boot the VM. Note the IP address it gets (`ip a` inside the VM) so you can reach the
   dashboard at `https://<vm-ip>` from your host browser.
6. Default login is `admin` / the password shown in the OVA's first-boot console output —
   change this immediately (`/var/ossec/bin/wazuh-passwords-tool` or the equivalent for your
   version).

### Option B: Manual install on a fresh Ubuntu VM

If you'd rather build the VM yourself (more portfolio-credible, since it demonstrates you
can do the install, not just import an appliance):

1. Create a new VirtualBox VM: Ubuntu Server 22.04 LTS, 4GB RAM, 2 vCPUs, 40GB disk, NAT
   network adapter.
2. Inside the VM, run the Wazuh all-in-one installation script:
   ```bash
   curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
   sudo bash ./wazuh-install.sh -a
   ```
3. This installs the Wazuh indexer, manager, and dashboard together. It'll print an admin
   password at the end — save it.
4. Confirm the manager is running:
   ```bash
   sudo systemctl status wazuh-manager
   ```

Either path gets you to the same place: a working Wazuh manager you can SSH into and a
dashboard reachable at `https://<vm-ip>`.

---

## Part 2 — Connecting Wazuh to AegisCloud's S3 Findings Export

Once `terraform/wazuh-integration` has been applied (see the main README's Phase 8), you'll
have:
- An S3 bucket: `aegiscloud-findings-export-<your-account-id>`
- An IAM access key pair, scoped to read-only on that one bucket/prefix

### Step 1 — Store the AWS credentials on the Wazuh VM

SSH into your Wazuh VM and configure a dedicated AWS CLI profile — **do not** put the
credentials directly in `ossec.conf`; Wazuh's aws-s3 wodle reads from the standard AWS
credentials file, which is the safer pattern (file permissions can be locked down to
600, and it's the same mechanism any other AWS tool on this box would use):

```bash
# On the Wazuh VM
sudo mkdir -p /root/.aws
sudo nano /root/.aws/credentials
```

Paste, using the values from `terraform output` in the `wazuh-integration` module:

```ini
[wazuh_aegiscloud_reader]
aws_access_key_id = <value from aegiscloud_wazuh_reader_access_key_id output>
aws_secret_access_key = <value from aegiscloud_wazuh_reader_secret_access_key output>
```

```bash
sudo chmod 600 /root/.aws/credentials
```

### Step 2 — Configure the aws-s3 wodle

Edit the manager config:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add this block **inside** the root `<ossec_config>` element (see
`docs/wazuh-ossec-aws-s3-wodle-snippet.xml` in this package for the exact block to
copy-paste):

```xml
<wodle name="aws-s3">
  <disabled>no</disabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <bucket type="custom">
    <name>aegiscloud-findings-export-YOUR_ACCOUNT_ID</name>
    <path>securityhub-findings/</path>
    <aws_profile>wazuh_aegiscloud_reader</aws_profile>
  </bucket>
</wodle>
```

Replace `YOUR_ACCOUNT_ID` with your real AWS account ID (from the `aegiscloud-findings-export-<account-id>`
bucket name Terraform created).

**What `interval` controls**: how often the wodle checks S3 for new objects. `5m` (5
minutes) is reasonable for testing — you can drop it to `1m` temporarily while validating
the end-to-end flow, then raise it back up once you've confirmed it works, since more
frequent polling has a (very small) cost and log-volume impact.

### Step 3 — Restart and validate

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/ossec.log | grep -i "aws-s3\|wodle"
```

You should see log lines confirming the wodle started and is checking the bucket. If
there's an auth error, double check the profile name in `ossec.conf` matches exactly what
you named it in `~/.aws/credentials`, and that the access key hasn't been rotated/deleted
since you copied it.

### Step 4 — Trigger a test finding and confirm it arrives

From your AWS side, run the same public-S3-bucket test described in Phase 5 of the main
README (make a test bucket public, let the remediation Lambda fire, which also generates a
Security Hub finding). Within one polling interval, you should see:

1. A new JSON object under `securityhub-findings/YYYY/MM/DD/` in the S3 bucket (check via
   AWS Console or `aws s3 ls`).
2. That same finding appear in the Wazuh dashboard — search for `aws-s3` as the log source,
   or filter by the `finding_id` field to confirm the specific test event landed.

### Step 5 (optional but recommended for your portfolio writeup) — Build a dashboard

In the Wazuh dashboard (OpenSearch Dashboards under the hood), create a simple
visualization filtered on your AegisCloud findings — a table of severity vs. count, or a
timeline of findings over the testing period. A screenshot of this is strong portfolio
evidence: it shows the full loop (AWS misconfiguration → detected → remediated → logged →
visible in an external SIEM you built yourself), not just isolated pieces.

---

## Known limitation worth stating honestly in an interview

The IAM user + long-lived access key used here is the simplest way to authenticate a
non-AWS system to S3, and it's genuinely fine for a portfolio/demo. In a production
environment, the harder-but-better answer is **IAM Roles Anywhere**, which lets an
on-premises/non-AWS system (like your Wazuh VM) assume a temporary IAM role using a
locally-issued X.509 certificate instead of a static access key — no long-lived credential
sitting on disk at all. If asked "how would you productionize this," that's the correct
answer, and knowing it (even if you didn't have time to implement it) is itself a good
signal.
