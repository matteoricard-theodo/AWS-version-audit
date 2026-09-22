# AWS version audit scripts

Automates the version discovery we did manually across the 3 NS AWS accounts (preprod, prod, legacy),
plus EOL/vuln enrichment.

## Files

- `aws_version_audit.py` : discovers EC2 + Lightsail instances per account, pulls OS/PHP/web server/DB/WordPress
  versions from every SSM reachable box. Read only, no destructive commands.
- `vuln_lookup.py` : takes the audit output and checks EOL status, PHP/WordPress compatibility, and best effort
  CVE counts.
- `main.py` : runs both in sequence.

## Prerequisites

- `aws` CLI installed
- `aws configure sso` set up, with a permission set that grants `ec2:DescribeInstances`,
  `lightsail:GetInstances`, `ssm:DescribeInstanceInformation`, `ssm:SendCommand`,
  `ssm:ListCommandInvocations`, `ssm:GetCommandInvocation`, `sts:GetCallerIdentity`
- Copy `accounts.example.json` to `accounts.json` and fill in your own SSO profile names, one entry per
  account to audit. `accounts.json` is gitignored since profile names are local to each machine.
- Active SSO session per profile before running: `aws sso login --profile <name>`
- Python 3.10+, no extra packages needed, stdlib only
- Network access to endoflife.date / api.osv.dev (and wpscan.com if using `WPSCAN_API_TOKEN`) for the
  enrichment step

## Usage

```
python3 main.py                                          # all accounts in ACCOUNTS
python3 main.py --profile X --region eu-west-3 --label Y  # one account only
WPSCAN_API_TOKEN=xxx python3 main.py                       # also pull WordPress core CVEs from WPScan
```

Can also run each step alone:

```
python3 aws_version_audit.py
python3 vuln_lookup.py output/audit.json
```

## Output

- `output/audit.json`, `output/audit.csv` : raw discovery, one row per instance, includes every WordPress
  install found (multi tenant Lightsail boxes host several sites) and Apache vhost dumps
- `output/vuln_report.json` : enriched version, EOL status per component, PHP to WordPress compatibility,
  recommended bump target, OSV CVE counts where applicable

## Data sources used

- `endoflife.date` : EOL/support dates for PHP, WordPress, MariaDB, Apache, nginx, Ubuntu, Debian. No API key.
- `api.osv.dev` : best effort CVE count for OS packaged components (EC2 only, Debian/Ubuntu ecosystem)
- `api.wpscan.com` : WordPress core CVEs, needs `WPSCAN_API_TOKEN` env var, skipped if absent

## Known caveats, read before trusting a number

- EOL has two dates: `support` (feature freeze, product still gets security patches after this) and `eol`
  (fully dead, no more patches). Only past `eol` counts as urgent. PHP 8.2 is a real example: support ended
  2024-12-31 but `eol` is 2026-12-31, so it is not urgent yet even though support ended.
- OSV Debian/Ubuntu ecosystem counts are a rough upper bound, not a precise "currently vulnerable" number.
  Distros backport security fixes without bumping the version string and OSV does not always reflect that.
- OSV is skipped for Lightsail/Bitnami components since those are bundled by Bitnami, not the OS package
  manager, the distro tracker has no visibility into them.
- PHP on the legacy account EC2 boxes (8.2/8.4) is newer than Ubuntu 22.04 ships by default (8.1), so it is
  almost certainly from a third party repo (sury.org or an ondrej style PPA). The official Ubuntu security
  tracker does not cover third party repos, so the OSV count for PHP there is flagged unreliable in the output.
- WordPress installs are found by locating `version.php`. A broken install missing that file will not show up,
  found 3 of those manually earlier (see main Notion audit), this script will not catch new ones the same way.
