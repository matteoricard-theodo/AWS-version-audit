#!/usr/bin/env python3
"""
Vulnerability / EOL enrichment for the output of aws_version_audit.py.

Reads output/audit.json (produced by aws_version_audit.py), and for every
component found (PHP, web server, database, WordPress installs) works out:

  - EOL status and recommended bump target, via endoflife.date (free, no key)
  - PHP <-> WordPress compatibility, via endoflife.date's wordpress.json
    supportedPHPVersions field
  - best-effort known-CVE count for OS-packaged components (EC2 boxes only),
    via OSV.dev's Debian/Ubuntu ecosystem data

Caveats, read before trusting the numbers:
  - OSV's Debian/Ubuntu ecosystem coverage is a rough upper bound, not a
    precise "currently vulnerable" count. Distro security teams frequently
    backport fixes without bumping the upstream version string, and OSV
    doesn't always reflect that. Treat it as "worth a second look", not gospel.
  - It is skipped entirely for Lightsail/Bitnami components, since those are
    bundled by Bitnami, not the OS package manager, and Debian/Ubuntu's
    tracker has no visibility into them.
  - PHP on the legacy-account EC2 boxes (8.2/8.4) is newer than what Ubuntu
    22.04 ships by default (8.1), so it almost certainly comes from a
    third-party repo (sury.org / ondrej PPA equivalent). Ubuntu's own
    security tracker doesn't cover third-party repos, so the OSV count for
    PHP on those boxes is flagged as unreliable rather than reported as fact.
  - WordPress core CVEs need WPScan (api.wpscan.com), which requires a free
    API token. Set WPSCAN_API_TOKEN to enable it; skipped otherwise.

Usage:
    python3 vuln_lookup.py [path/to/audit.json]
"""

import json
import re
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DEFAULT_INPUT = SCRIPT_DIR / "output" / "audit.json"
DEFAULT_OUTPUT = SCRIPT_DIR / "output" / "vuln_report.json"

ENDOFLIFE_SLUGS = {
    "php": "php",
    "wordpress": "wordpress",
    "mariadb": "mariadb",
    "apache": "apache-http-server",
    "nginx": "nginx",
    "ubuntu": "ubuntu",
    "debian": "debian",
}

WPSCAN_API_TOKEN = None  # set via env var WPSCAN_API_TOKEN, read in main()

_cycle_cache: dict = {}


def http_get(url: str, headers: dict | None = None) -> dict | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def http_post_json(url: str, payload: dict, headers: dict | None = None) -> dict | None:
    body = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def get_cycles(product_key: str) -> list:
    if product_key in _cycle_cache:
        return _cycle_cache[product_key]
    slug = ENDOFLIFE_SLUGS.get(product_key, product_key)
    data = http_get(f"https://endoflife.date/api/{slug}.json") or []
    _cycle_cache[product_key] = data
    return data


def version_tuple(v: str) -> tuple:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:4]) or (0,)


def find_cycle(cycles: list, version: str) -> dict | None:
    candidates = [c for c in cycles if version.startswith(str(c["cycle"]))]
    candidates.sort(key=lambda c: len(str(c["cycle"])), reverse=True)
    for c in candidates:
        cyc = str(c["cycle"])
        if version == cyc or version[len(cyc):len(cyc) + 1] == ".":
            return c
    return None


def parse_date_field(value) -> date | None:
    """endoflife.date fields (eol, support) are either an ISO date string or
    the boolean false (meaning 'no such date / not applicable')."""
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def eol_check(product_key: str, version: str) -> dict:
    cycles = get_cycles(product_key)
    if not cycles:
        return {"status": "lookup_failed"}
    cycle = find_cycle(cycles, version)
    top = cycles[0]  # endoflife.date lists newest cycle first
    recommended = f"{top['cycle']} (latest: {top.get('latest', '?')})"
    if cycle is None:
        return {
            "status": "unknown_cycle",
            "recommended_target": recommended,
            "note": f"version {version} did not match any known {product_key} cycle",
        }

    today = date.today()
    eol_date = parse_date_field(cycle.get("eol"))
    support_date = parse_date_field(cycle.get("support"))

    if eol_date is not None and eol_date <= today:
        status = "eol"  # fully end of life: no more security patches at all
    elif support_date is not None and support_date <= today:
        status = "security_only"  # active support ended, security patches still land
    else:
        status = "supported"

    return {
        "status": status,
        "cycle": cycle["cycle"],
        "eol_date": cycle.get("eol") if isinstance(cycle.get("eol"), str) else None,
        "support_until": cycle.get("support") if isinstance(cycle.get("support"), str) else None,
        "latest_in_cycle": cycle.get("latest"),
        "recommended_target": recommended if (status != "supported" or cycle["cycle"] != top["cycle"]) else None,
    }


def parse_php_range(range_str: str) -> tuple | None:
    m = re.match(r"\s*([\d.]+)\s*-\s*([\d.]+)\s*", range_str or "")
    if not m:
        return None
    return version_tuple(m.group(1)), version_tuple(m.group(2))


def wp_php_compatibility(wp_version: str, php_version: str) -> dict:
    cycles = get_cycles("wordpress")
    cycle = find_cycle(cycles, wp_version)
    if cycle is None:
        return {"status": "unknown"}
    rng = parse_php_range(cycle.get("supportedPHPVersions", ""))
    if rng is None:
        return {"status": "unknown"}
    lo, hi = rng
    php_v = version_tuple(php_version)
    compatible = lo <= php_v <= hi
    return {
        "status": "compatible" if compatible else "incompatible",
        "wp_supported_php_range": cycle.get("supportedPHPVersions"),
    }


DEBIAN_UBUNTU_PACKAGE_NAMES = {
    "apache": "apache2",
}


def osv_check(package: str, ecosystem: str, version: str) -> dict:
    result = http_post_json(
        "https://api.osv.dev/v1/query",
        {"version": version, "package": {"name": package, "ecosystem": ecosystem}},
    )
    if result is None:
        return {"status": "lookup_failed"}
    vulns = result.get("vulns", [])
    return {
        "status": "ok",
        "count": len(vulns),
        "ids": [v["id"] for v in vulns][:15],
        "note": "OSV Debian/Ubuntu data is a rough upper bound, not a precise "
                "'currently vulnerable' signal, see script docstring",
    }


def os_to_ecosystem(os_string: str) -> tuple | None:
    m = re.search(r"Ubuntu\s+(\d+\.\d+)", os_string)
    if m:
        return "Ubuntu", m.group(1)
    m = re.search(r"Debian.*?\s(\d+)\s*\(", os_string)
    if m:
        return "Debian", m.group(1)
    return None


def wpscan_check(wp_version: str) -> dict:
    if not WPSCAN_API_TOKEN:
        return {"status": "skipped", "note": "set WPSCAN_API_TOKEN env var to enable"}
    data = http_get(
        f"https://wpscan.com/api/v3/wordpresses/{wp_version}",
        headers={"Authorization": f"Token token={WPSCAN_API_TOKEN}"},
    )
    if data is None:
        return {"status": "lookup_failed"}
    key = next(iter(data), None)
    vulns = data.get(key, {}).get("vulnerabilities", []) if key else []
    return {"status": "ok", "count": len(vulns), "titles": [v.get("title") for v in vulns]}


def enrich_record(record: dict) -> dict:
    out = {
        "account_label": record["account_label"],
        "name": record["name"],
        "kind": record["kind"],
        "public_ip": record["public_ip"],
        "findings": [],
    }
    if record.get("status") != "success":
        out["findings"].append({"component": "instance", "note": f"not checked: {record.get('status')}"})
        return out

    is_os_packaged = record["kind"] == "ec2"
    ecosystem_info = os_to_ecosystem(record.get("os", "")) if is_os_packaged else None

    php_match = re.search(r"PHP\s+([\d.]+)", record.get("php", ""))
    if php_match:
        php_version = php_match.group(1)
        finding = {"component": "php", "version": php_version, "eol": eol_check("php", php_version)}
        if ecosystem_info:
            eco, ver = ecosystem_info
            major_minor = ".".join(php_version.split(".")[:2])
            finding["osv"] = osv_check(f"php{major_minor}", f"{eco}:{ver}", php_version)
            finding["osv"]["caveat"] = (
                "PHP 8.2+ on Ubuntu 22.04 is almost certainly from a third-party repo "
                "(sury.org / ondrej PPA), not the official archive, official security "
                "tracker has no visibility into it, treat this count as unreliable."
            )
        out["findings"].append(finding)

    apache_match = re.search(r"Apache/([\d.]+)", record.get("webserver", ""))
    if apache_match:
        apache_version = apache_match.group(1)
        finding = {"component": "apache", "version": apache_version, "eol": eol_check("apache", apache_version)}
        if ecosystem_info:
            eco, ver = ecosystem_info
            finding["osv"] = osv_check("apache2", f"{eco}:{ver}", apache_version)
        out["findings"].append(finding)

    db_match = re.search(r"Distrib\s+([\d.]+)-MariaDB", record.get("db", ""))
    if db_match:
        db_version = db_match.group(1)
        finding = {"component": "mariadb", "version": db_version, "eol": eol_check("mariadb", db_version)}
        if ecosystem_info:
            eco, ver = ecosystem_info
            major_minor = ".".join(db_version.split(".")[:2])
            finding["osv"] = osv_check(f"mariadb-{major_minor}", f"{eco}:{ver}", db_version)
        out["findings"].append(finding)

    for wp in record.get("wp_installs", []):
        wp_version = wp["version"]
        if wp_version in ("", "UNKNOWN"):
            continue
        finding = {
            "component": "wordpress",
            "path": wp["path"],
            "version": wp_version,
            "eol": eol_check("wordpress", wp_version),
        }
        if php_match:
            finding["php_compatibility"] = wp_php_compatibility(wp_version, php_match.group(1))
        finding["wpscan"] = wpscan_check(wp_version)
        out["findings"].append(finding)

    return out


def print_summary(enriched: list) -> None:
    print("\n" + "=" * 100)
    for rec in enriched:
        flagged = [
            f for f in rec["findings"]
            if f.get("eol", {}).get("status") in ("eol", "security_only")
            or f.get("php_compatibility", {}).get("status") == "incompatible"
            or f.get("osv", {}).get("count", 0) > 0
        ]
        if not flagged:
            continue
        print(f"[{rec['account_label']}] {rec['name']} ({rec['public_ip']})")
        for f in flagged:
            bits = [f"  - {f['component']} {f.get('version', '')}"]
            eol = f.get("eol", {})
            if eol.get("status") == "eol":
                bits.append(f"EOL since {eol.get('eol_date')} (URGENT), bump to {eol.get('recommended_target')}")
            elif eol.get("status") == "security_only":
                bits.append(
                    f"active support ended {eol.get('support_until')}, still gets security "
                    f"patches until {eol.get('eol_date')}, plan a bump but not urgent"
                )
            compat = f.get("php_compatibility", {})
            if compat.get("status") == "incompatible":
                bits.append(f"PHP incompatible (WP needs {compat.get('wp_supported_php_range')})")
            osv = f.get("osv", {})
            if osv.get("count", 0) > 0:
                bits.append(f"OSV: {osv['count']} potential CVEs (rough signal)")
            print(", ".join(bits))
    print("=" * 100)


def main() -> None:
    global WPSCAN_API_TOKEN
    import os
    WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN")

    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    if not input_path.exists():
        print(f"no input at {input_path}, run aws_version_audit.py first", file=sys.stderr)
        sys.exit(1)

    records = json.loads(input_path.read_text())
    enriched = [enrich_record(r) for r in records]

    print_summary(enriched)

    DEFAULT_OUTPUT.parent.mkdir(exist_ok=True)
    DEFAULT_OUTPUT.write_text(json.dumps(enriched, indent=2))
    print(f"\nwrote {DEFAULT_OUTPUT}")


if __name__ == "__main__":
    main()
