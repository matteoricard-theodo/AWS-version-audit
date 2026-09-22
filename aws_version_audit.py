#!/usr/bin/env python3
"""
AWS version audit across NS accounts.

Discovers EC2 + Lightsail instances in each configured (profile, region),
pulls OS/PHP/web server/DB/WordPress core versions from every SSM-reachable
box in one combined command per account, and writes structured JSON + a
flat CSV to ./output/.

Read only. Runs no destructive commands. Requires: aws CLI configured with
SSO profiles, no other Python dependencies (stdlib only).

The list of (profile, region) pairs to audit lives in accounts.json next to
this script, not hardcoded, since profile names are local to each machine.
Copy accounts.example.json to accounts.json and fill in your own profiles.

Usage:
    python3 aws_version_audit.py
    python3 aws_version_audit.py --profile NS-FullAdmin-prod --region eu-west-3
"""

import argparse
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
OUTPUT_DIR = SCRIPT_DIR / "output"
ACCOUNTS_FILE = SCRIPT_DIR / "accounts.json"
ACCOUNTS_EXAMPLE_FILE = SCRIPT_DIR / "accounts.example.json"


def load_accounts() -> list[dict]:
    if not ACCOUNTS_FILE.exists():
        print(
            f"no {ACCOUNTS_FILE.name} found next to the script.\n"
            f"copy {ACCOUNTS_EXAMPLE_FILE.name} to {ACCOUNTS_FILE.name} and fill in your "
            f"own AWS SSO profile names, or run with --profile for a one-off account.",
            file=sys.stderr,
        )
        return []
    return json.loads(ACCOUNTS_FILE.read_text())

POLL_INTERVAL_SECONDS = 4
POLL_TIMEOUT_SECONDS = 180

DIAGNOSTIC_SCRIPT = r"""
echo ===HOST===
hostname -I | awk '{print $1}'
echo ===OS===
grep PRETTY_NAME /etc/os-release
echo ===KERNEL===
uname -r
echo ===PHP===
if command -v php >/dev/null 2>&1; then
  php -v 2>/dev/null | head -1
elif [ -x /opt/bitnami/php/bin/php ]; then
  /opt/bitnami/php/bin/php -v 2>/dev/null | head -1
else
  echo NONE
fi
echo ===WEBSERVER===
if command -v apache2 >/dev/null 2>&1; then
  apache2 -v 2>/dev/null | head -1
elif [ -x /opt/bitnami/apache/bin/httpd ]; then
  /opt/bitnami/apache/bin/httpd -v 2>/dev/null | head -1
elif command -v nginx >/dev/null 2>&1; then
  nginx -v 2>&1 | head -1
else
  echo NONE
fi
echo ===DB===
{ mysql --version 2>/dev/null; } \
  || { mariadb --version 2>/dev/null; } \
  || { /opt/bitnami/mysql/bin/mysql --version 2>/dev/null; } \
  || echo NONE
echo ===WPINSTALLS===
for base in /var/www /opt/bitnami; do
  find "$base" -maxdepth 4 -iname version.php -path "*wp-includes*" 2>/dev/null
done | sort -u | while read -r f; do
  d=$(dirname "$(dirname "$f")")
  v=$(grep -E "wp_version = " "$f" 2>/dev/null | head -1 | sed -E "s/.*= '([^']+)'.*/\1/")
  echo "$d :: ${v:-UNKNOWN}"
done
echo ===VHOSTS===
for f in /etc/apache2/sites-enabled/* /opt/bitnami/apache/conf/vhosts/*.conf; do
  [ -f "$f" ] || continue
  echo "-- $f --"
  grep -E "ServerName|ServerAlias|DocumentRoot" "$f" 2>/dev/null
done
echo ===END===
""".strip()


@dataclass
class Instance:
    id: str
    kind: str  # "ec2" or "lightsail"
    name: str
    state: str
    public_ip: str = ""
    private_ip: str = ""
    ssm_online: bool = False


@dataclass
class Result:
    profile: str
    label: str
    instance: Instance
    status: str = "not_attempted"
    os: str = ""
    kernel: str = ""
    php: str = ""
    webserver: str = ""
    db: str = ""
    wp_installs: list = field(default_factory=list)
    vhosts: str = ""
    raw_stdout: str = ""
    error: str = ""


def get_account_id(profile: str, region: str) -> str | None:
    data, err = aws_json(profile, region, "sts", "get-caller-identity")
    if data is None:
        print(f"  [warn] sts get-caller-identity failed: {err}", file=sys.stderr)
        return None
    return data.get("Account")


def aws_json(profile: str, region: str, *args: str):
    cmd = ["aws", "--profile", profile, "--region", region, *args, "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, proc.stderr.strip()
    text = proc.stdout.strip()
    if not text:
        return {}, ""
    return json.loads(text), ""


def get_ec2_instances(profile: str, region: str) -> list[Instance]:
    data, err = aws_json(profile, region, "ec2", "describe-instances")
    if data is None:
        print(f"  [warn] ec2 describe-instances failed: {err}", file=sys.stderr)
        return []
    out = []
    for res in data.get("Reservations", []):
        for inst in res.get("Instances", []):
            name = next(
                (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), ""
            )
            out.append(
                Instance(
                    id=inst["InstanceId"],
                    kind="ec2",
                    name=name or inst["InstanceId"],
                    state=inst["State"]["Name"],
                    public_ip=inst.get("PublicIpAddress", ""),
                    private_ip=inst.get("PrivateIpAddress", ""),
                )
            )
    return out


def get_lightsail_instances(profile: str, region: str) -> list[Instance]:
    data, err = aws_json(profile, region, "lightsail", "get-instances")
    if data is None:
        # Lightsail may be unused in this account/region; not fatal.
        return []
    out = []
    for inst in data.get("instances", []):
        out.append(
            Instance(
                id=inst["name"],  # Lightsail has no instance-id; keyed by name for now
                kind="lightsail",
                name=inst["name"],
                state=inst.get("state", {}).get("name", "unknown"),
                public_ip=inst.get("publicIpAddress", ""),
                private_ip=inst.get("privateIpAddress", ""),
            )
        )
    return out


def get_ssm_online_map(profile: str, region: str) -> dict:
    """Returns {ip_address: ssm_instance_id} for every SSM-managed instance that is Online."""
    data, err = aws_json(profile, region, "ssm", "describe-instance-information")
    if data is None:
        print(f"  [warn] ssm describe-instance-information failed: {err}", file=sys.stderr)
        return {}
    online = {}
    for info in data.get("InstanceInformationList", []):
        if info.get("PingStatus") == "Online":
            ip = info.get("IPAddress", "")
            online[ip] = info["InstanceId"]
            # EC2 instances are also keyed by their own instance id directly.
            online[info["InstanceId"]] = info["InstanceId"]
    return online


def resolve_ssm_targets(instances: list[Instance], ssm_online: dict) -> None:
    """Mutates instances in place: sets .id to the real SSM id and .ssm_online flag."""
    for inst in instances:
        if inst.kind == "ec2":
            if ssm_online.get(inst.id) == inst.id:
                inst.ssm_online = True
        elif inst.kind == "lightsail":
            ssm_id = ssm_online.get(inst.private_ip)
            if ssm_id:
                inst.id = ssm_id
                inst.ssm_online = True


def send_diagnostic_command(profile: str, region: str, target_ids: list[str]) -> str | None:
    if not target_ids:
        return None
    params = json.dumps({"commands": DIAGNOSTIC_SCRIPT.splitlines()})
    cmd = [
        "aws", "--profile", profile, "--region", region,
        "ssm", "send-command",
        "--document-name", "AWS-RunShellScript",
        "--instance-ids", *target_ids,
        "--parameters", params,
        "--query", "Command.CommandId",
        "--output", "text",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"  [warn] send-command failed: {proc.stderr.strip()}", file=sys.stderr)
        return None
    return proc.stdout.strip()


TERMINAL_STATUSES = {"Success", "Failed", "Cancelled", "TimedOut", "Undeliverable", "Terminated"}


def poll_command_statuses(profile: str, region: str, command_id: str, expected: int) -> dict:
    """Cheap polling loop: returns {instance_id: status} once every invocation is terminal.

    Deliberately ignores list-command-invocations' Output field, which is
    truncated to ~2500 chars server-side. Full output is fetched separately
    via get-command-invocation once everything is done.
    """
    deadline = time.time() + POLL_TIMEOUT_SECONDS
    statuses = {}
    while time.time() < deadline:
        data, err = aws_json(
            profile, region, "ssm", "list-command-invocations",
            "--command-id", command_id,
        )
        if data:
            invocations = data.get("CommandInvocations", [])
            statuses = {inv["InstanceId"]: inv.get("Status", "Unknown") for inv in invocations}
            done = [s for s in statuses.values() if s in TERMINAL_STATUSES]
            if len(done) >= expected and len(statuses) >= expected:
                break
        time.sleep(POLL_INTERVAL_SECONDS)
    return statuses


def fetch_full_invocation(profile: str, region: str, command_id: str, instance_id: str) -> dict:
    data, err = aws_json(
        profile, region, "ssm", "get-command-invocation",
        "--command-id", command_id, "--instance-id", instance_id,
    )
    if data is None:
        return {"Status": "fetch_failed", "StandardOutputContent": "", "StandardErrorContent": err}
    return data


def fetch_all_full_invocations(profile: str, region: str, command_id: str, instance_ids: list[str]) -> dict:
    """Parallel fetch of full (untruncated) output for every instance, once all are terminal."""
    results = {}
    with ThreadPoolExecutor(max_workers=min(10, len(instance_ids) or 1)) as pool:
        futures = {
            pool.submit(fetch_full_invocation, profile, region, command_id, iid): iid
            for iid in instance_ids
        }
        for future in futures:
            iid = futures[future]
            results[iid] = future.result()
    return results


def parse_diagnostic_output(stdout: str) -> dict:
    sections = re.split(r"^===(\w+)===$", stdout, flags=re.MULTILINE)
    # sections[0] is preamble; then alternating name, body
    data = {}
    for i in range(1, len(sections) - 1, 2):
        name = sections[i].strip()
        body = sections[i + 1].strip()
        data[name] = body

    wp_installs = []
    for line in data.get("WPINSTALLS", "").splitlines():
        line = line.strip()
        if "::" in line:
            path, version = line.split("::", 1)
            wp_installs.append({"path": path.strip(), "version": version.strip()})

    return {
        "os": data.get("OS", "").replace("PRETTY_NAME=", "").strip('"'),
        "kernel": data.get("KERNEL", ""),
        "php": data.get("PHP", "NONE"),
        "webserver": data.get("WEBSERVER", "NONE"),
        "db": data.get("DB", "NONE"),
        "wp_installs": wp_installs,
        "vhosts": data.get("VHOSTS", ""),
    }


def audit_account(profile: str, label: str, region: str) -> list[Result]:
    print(f"[{label}] {profile} / {region}")

    ec2 = get_ec2_instances(profile, region)
    lightsail = get_lightsail_instances(profile, region)
    all_instances = ec2 + lightsail
    print(f"  found {len(ec2)} EC2, {len(lightsail)} Lightsail")

    ssm_online = get_ssm_online_map(profile, region)
    resolve_ssm_targets(all_instances, ssm_online)

    reachable = [i for i in all_instances if i.ssm_online]
    unreachable = [i for i in all_instances if not i.ssm_online]
    print(f"  {len(reachable)} reachable via SSM, {len(unreachable)} not")

    results = [
        Result(profile=profile, label=label, instance=i, status="unreachable")
        for i in unreachable
    ]

    if reachable:
        target_ids = [i.id for i in reachable]
        command_id = send_diagnostic_command(profile, region, target_ids)
        if command_id:
            print(f"  ran diagnostic command {command_id}, polling for completion...")
            statuses = poll_command_statuses(profile, region, command_id, len(target_ids))
            print(f"  fetching full output for {len(target_ids)} instances...")
            invocations = fetch_all_full_invocations(profile, region, command_id, target_ids)
            for inst in reachable:
                status = statuses.get(inst.id, "timed_out")
                inv = invocations.get(inst.id, {})
                if status != "Success":
                    results.append(Result(profile=profile, label=label, instance=inst,
                                           status=status,
                                           error=inv.get("StandardErrorContent", "")))
                    continue
                stdout = inv.get("StandardOutputContent", "")
                parsed = parse_diagnostic_output(stdout)
                results.append(Result(
                    profile=profile, label=label, instance=inst, status="success",
                    raw_stdout=stdout, **parsed,
                ))
        else:
            for inst in reachable:
                results.append(Result(profile=profile, label=label, instance=inst,
                                       status="send_command_failed"))

    return results


def write_outputs(all_results: list[Result]) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    json_path = OUTPUT_DIR / "audit.json"
    json_data = []
    for r in all_results:
        json_data.append({
            "account_label": r.label,
            "profile": r.profile,
            "instance_id": r.instance.id,
            "name": r.instance.name,
            "kind": r.instance.kind,
            "state": r.instance.state,
            "public_ip": r.instance.public_ip,
            "private_ip": r.instance.private_ip,
            "status": r.status,
            "os": r.os,
            "kernel": r.kernel,
            "php": r.php,
            "webserver": r.webserver,
            "db": r.db,
            "wp_installs": r.wp_installs,
            "vhosts": r.vhosts,
            "error": r.error,
            "raw_stdout": r.raw_stdout,
        })
    json_path.write_text(json.dumps(json_data, indent=2))
    print(f"\nwrote {json_path}")

    csv_path = OUTPUT_DIR / "audit.csv"
    with csv_path.open("w") as f:
        f.write("account,name,kind,public_ip,status,os,php,webserver,db,wp_installs\n")
        for r in all_results:
            wp = "; ".join(f"{w['path']}={w['version']}" for w in r.wp_installs)
            row = [
                r.label, r.instance.name, r.instance.kind, r.instance.public_ip,
                r.status, r.os, r.php, r.webserver, r.db, wp,
            ]
            f.write(",".join(f'"{str(v).replace(chr(34), chr(39))}"' for v in row) + "\n")
    print(f"wrote {csv_path}")


def print_summary(all_results: list[Result]) -> None:
    print("\n" + "=" * 100)
    for r in all_results:
        print(f"[{r.label}] {r.instance.name} ({r.instance.public_ip or 'no public ip'}) -> {r.status}")
        if r.status == "success":
            print(f"    OS: {r.os}")
            print(f"    PHP: {r.php}")
            print(f"    Web: {r.webserver}")
            print(f"    DB: {r.db}")
            for w in r.wp_installs:
                print(f"    WP [{w['path']}]: {w['version']}")
    print("=" * 100)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", help="Only audit this single AWS profile")
    parser.add_argument("--region", default="eu-west-3", help="Region to use with --profile")
    parser.add_argument(
        "--label",
        help="Override the account label. Defaults to the real AWS account id "
             "(via sts get-caller-identity), falls back to the profile name if that fails.",
    )
    args = parser.parse_args()

    if args.profile:
        label = args.label or get_account_id(args.profile, args.region) or args.profile
        accounts = [{"profile": args.profile, "label": label, "region": args.region}]
    else:
        accounts = load_accounts()
        if not accounts:
            sys.exit(1)

    all_results: list[Result] = []
    for acc in accounts:
        all_results.extend(audit_account(acc["profile"], acc["label"], acc["region"]))

    print_summary(all_results)
    write_outputs(all_results)


if __name__ == "__main__":
    main()
