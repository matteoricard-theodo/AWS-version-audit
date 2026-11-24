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
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DEFAULT_INPUT = SCRIPT_DIR / "output" / "audit.json"
DEFAULT_OUTPUT = SCRIPT_DIR / "output" / "vuln_report.json"
EXCLUSIONS_FILE = SCRIPT_DIR / "exclusions.json"
TARGETS_FILE = SCRIPT_DIR / "targets.json"


def load_targets() -> dict:
    """Declared target versions, a team decision (e.g. "we're moving the
    whole fleet to PHP 8.5"), independent of whatever endoflife.date
    recommends as the latest cycle. Per-machine overrides win over the
    global default. Returns {} (no declared targets) if the file is absent."""
    if not TARGETS_FILE.exists():
        return {}
    return json.loads(TARGETS_FILE.read_text())


def target_for(targets: dict, component: str, machine_name: str) -> str | None:
    override = targets.get("overrides", {}).get(machine_name, {})
    if component in override:
        return override[component]
    return targets.get(component)


def load_exclusions() -> dict:
    """Machine names to drop from the report, with a reason kept for
    traceability, e.g. decommissioned or removed at the client's request.
    Does not affect aws_version_audit.py, the raw inventory in audit.json
    always stays complete, only the human-facing report is filtered."""
    if not EXCLUSIONS_FILE.exists():
        return {}
    entries = json.loads(EXCLUSIONS_FILE.read_text())
    return {e["name"]: e.get("reason", "") for e in entries}

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


SOON_EOL_THRESHOLD_DAYS = 90


def eol_check(product_key: str, version: str) -> dict:
    """
    Two separate, combinable signals live in the result, since a version can
    need both at once (e.g. PHP 8.2.10: bump to 8.2.33 fixes known issues
    right now, but 8.2 is also approaching its own end of life, so a later
    move to 8.3/8.4/8.5 is needed regardless):

      - outdated_patch: a newer release exists WITHIN the same cycle
        (a same-cycle bump, e.g. 8.2.10 -> 8.2.33), fixes known CVEs, cheap
        and low risk, do this first regardless of the cycle's own EOL status.
      - status / soon_eol: whether the CYCLE ITSELF is dead, dying soon, or
        fine, this drives whether a cycle migration (e.g. 8.2 -> 8.5) is
        also needed, separately from the in-cycle patch above.
    """
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

    days_to_eol = (eol_date - today).days if eol_date is not None else None
    soon_eol = (
        status == "supported"
        and days_to_eol is not None
        and 0 < days_to_eol <= SOON_EOL_THRESHOLD_DAYS
    )

    latest_in_cycle = cycle.get("latest")
    outdated_patch = (
        status != "eol"  # leaving the cycle entirely makes an in-cycle bump moot
        and latest_in_cycle is not None
        and version_tuple(version) < version_tuple(latest_in_cycle)
    )

    return {
        "status": status,
        "soon_eol": soon_eol,
        "days_to_eol": days_to_eol,
        "outdated_patch": outdated_patch,
        "cycle": cycle["cycle"],
        "eol_date": cycle.get("eol") if isinstance(cycle.get("eol"), str) else None,
        "support_until": cycle.get("support") if isinstance(cycle.get("support"), str) else None,
        "latest_in_cycle": latest_in_cycle,
        "recommended_target": recommended if (status != "supported" or cycle["cycle"] != top["cycle"]) else None,
        "recommended_target_version": top.get("latest"),
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
    # supportedPHPVersions bounds are major.minor only ("7.4 - 8.5"), compare
    # at the same precision, otherwise 8.5.10 wrongly reads as > 8.5 since
    # (8,5,10) > (8,5) in a plain tuple comparison.
    php_v = version_tuple(php_version)[:max(len(lo), len(hi))]
    compatible = lo <= php_v <= hi
    return {
        "status": "compatible" if compatible else "incompatible",
        "wp_supported_php_range": cycle.get("supportedPHPVersions"),
    }


DEBIAN_UBUNTU_PACKAGE_NAMES = {
    "apache": "apache2",
}

CVSS_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0, "L": 0.22, "H": 0.56},
    "I": {"N": 0, "L": 0.22, "H": 0.56},
    "A": {"N": 0, "L": 0.22, "H": 0.56},
    # PR depends on Scope, handled separately below.
}
CVSS_V3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS_V3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def cvss_v3_base_score(vector: str) -> float | None:
    """Computes the CVSS v3.x base score from a vector string
    (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). OSV gives us the
    vector, not the number, this is the official formula from the CVSS v3.1
    spec section 7.1, base metrics only (temporal/environmental not used
    since OSV doesn't supply them)."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
        scope_changed = parts.get("S") == "C"
        pr_table = CVSS_V3_PR_CHANGED if scope_changed else CVSS_V3_PR_UNCHANGED

        av = CVSS_V3_WEIGHTS["AV"][parts["AV"]]
        ac = CVSS_V3_WEIGHTS["AC"][parts["AC"]]
        pr = pr_table[parts["PR"]]
        ui = CVSS_V3_WEIGHTS["UI"][parts["UI"]]
        c = CVSS_V3_WEIGHTS["C"][parts["C"]]
        i = CVSS_V3_WEIGHTS["I"][parts["I"]]
        a = CVSS_V3_WEIGHTS["A"][parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) * (1.08 if scope_changed else 1)
    raw = min(raw, 10)
    import math
    return math.ceil(raw * 10) / 10  # CVSS "round up" rule, not standard rounding


def summarize_osv_vuln(v: dict) -> dict:
    cvss_score, cvss_vector, qualitative = None, None, None
    for s in severity_entries(v):
        if s.get("type") == "CVSS_V3" and cvss_vector is None:
            cvss_vector = s["score"]
            cvss_score = cvss_v3_base_score(cvss_vector)
        elif s.get("type") in ("Ubuntu", "Debian") and qualitative is None:
            qualitative = s["score"]

    summary = v.get("summary") or v.get("details") or ""
    if len(summary) > 220:
        summary = summary[:217] + "..."

    return {
        "id": v["id"],
        "summary": summary,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "qualitative": qualitative,
    }


def trusted_package_version_checked(manifest_version: str | None, live_version: str) -> tuple:
    """A manifest (dpkg, .bitnami_components.json) can go stale relative to
    what's actually running, verified in practice: a Lightsail box's own
    .bitnami_components.json still claimed PHP "8.2.28-11" while the live
    php -v on that exact box said 8.2.33, PHP had been patched by hand
    outside Bitnami's tracking. Blindly trusting the manifest queried OSV
    for the wrong version entirely and mislabeled the result under the live
    version's name. Only trust the manifest when its bare version actually
    matches what's live, otherwise fall back to the live version, less
    precise (no build suffix) but never outright wrong. Also reports
    whether the manifest was usable, so callers can warn when it wasn't (a
    mismatch is itself a
    signal, e.g. verified in practice: a box's dpkg mariadb-server version
    used "+maria~ubu2204", a MariaDB-corp-repo marker rather than the
    standard Ubuntu archive suffix another otherwise-identical box had)."""
    if not manifest_version:
        return live_version, False
    # dpkg versions can carry an epoch prefix ("1:10.6.24-0ubuntu...", common
    # for database packages), strip it before comparing the bare version.
    bare = manifest_version.split(":", 1)[-1].split("-")[0]
    if bare == live_version:
        return manifest_version, True
    return live_version, False


def osv_check_with_manifest(package: str, ecosystem: str, manifest_version, live_version: str) -> dict:
    """osv_check, using the manifest version when it's consistent with what
    was actually detected live, falling back to the live version otherwise,
    and flagging the mismatch itself as worth a look (it can mean the
    package came from a non-standard repo)."""
    version, matched = trusted_package_version_checked(manifest_version, live_version)
    result = osv_check(package, ecosystem, version)
    if manifest_version and not matched:
        mismatch_note = (
            f"the package manifest reported a different version ({manifest_version}) than the "
            f"live check ({live_version}), used the live version instead, the mismatch itself "
            f"can mean a non-standard install (e.g. a vendor repo instead of the distro's own)."
        )
        existing = result.get("caveat", "")
        result["caveat"] = f"{existing} {mismatch_note}".strip() if existing else mismatch_note
    return result


def dismissed_by_distro(v: dict, ecosystem: str) -> bool:
    """Debian's own tracker marks some CVEs "unimportant" urgency, meaning
    their security team assessed it and decided it's not worth fixing (often
    the code path isn't reachable in Debian's build, or it's theoretical).
    Those never get a "fixed" event so OSV lists them as affecting every
    version forever, verified in practice (Apache 2.4.68: 8 such entries,
    some against CVE IDs from 2001-2008). Ubuntu doesn't expose this field,
    this only filters Debian entries, it's a no-op elsewhere."""
    for aff in v.get("affected", []):
        if aff.get("package", {}).get("ecosystem") != ecosystem:
            continue
        if aff.get("ecosystem_specific", {}).get("urgency") == "unimportant":
            return True
    return False


def severity_entries(v: dict) -> list:
    """OSV is inconsistent about where it puts the severity array: Debian/
    Ubuntu ecosystem entries carry it at the top level of the vuln object,
    Bitnami ecosystem entries carry it per affected-package instead (verified:
    top level was empty for every single Bitnami entry, all 22/36/11/5 got
    wrongly excluded as "unassessed" until this checked both places)."""
    entries = list(v.get("severity", []) or [])
    for aff in v.get("affected", []) or []:
        entries.extend(aff.get("severity", []) or [])
    return entries


def has_real_assessment(v: dict) -> bool:
    """True only if some security team actually looked at this CVE and
    scored it, either a CVSS vector or a distro qualitative rating that
    isn't "not yet assigned". Verified in practice on this exact fleet: all
    10 "PHP 8.2.33 has CVEs" entries were Debian urgency "not yet assigned"
    (nobody has triaged them, could be anything), while rapid7's real scan
    of the same domains never flagged PHP at all, only WordPress core and
    plugin CVEs (which this tool doesn't track yet). Meanwhile the 44
    MariaDB 10.6 entries were all Ubuntu "medium", genuinely assessed. Same
    OSV mechanism, very different confidence, this is the difference."""
    for s in severity_entries(v):
        if s.get("type") == "CVSS_V3":
            return True
        if s.get("type") in ("Ubuntu", "Debian") and s.get("score") not in (None, "not yet assigned"):
            return True
    return False


def osv_check(package: str, ecosystem: str, version: str) -> dict:
    result = http_post_json(
        "https://api.osv.dev/v1/query",
        {"version": version, "package": {"name": package, "ecosystem": ecosystem}},
    )
    if result is None:
        return {"status": "lookup_failed"}
    all_vulns = result.get("vulns", [])
    dismissed = sum(1 for v in all_vulns if dismissed_by_distro(v, ecosystem))
    unassessed = sum(1 for v in all_vulns if not dismissed_by_distro(v, ecosystem) and not has_real_assessment(v))
    vulns = [v for v in all_vulns if not dismissed_by_distro(v, ecosystem) and has_real_assessment(v)]
    items = [summarize_osv_vuln(v) for v in vulns[:30]]
    is_distro = ecosystem.startswith("Debian") or ecosystem.startswith("Ubuntu")
    note_bits = [
        f"Queried against OSV's {ecosystem} data with the exact installed package version"
        + (", not just the upstream version." if is_distro else ".")
    ]
    if dismissed:
        note_bits.append(f"{dismissed} distro-dismissed (\"unimportant\") entries excluded.")
    if unassessed:
        note_bits.append(
            f"{unassessed} entries excluded for having no severity assessment at all, too "
            "speculative to call a CVE."
        )
    note = " ".join(note_bits)
    return {
        "status": "ok",
        "count": len(vulns),
        "ids": [v["id"] for v in vulns][:15],
        "items": items,
        "note": note,
    }


NVD_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ns-mcs-version-audit/1.0)"}
# NVD's anonymous API silently degrades (200 OK, totalResults set, but an
# empty vulnerabilities array) without a browser-like User-Agent, and
# separately throttles to a handful of requests per 30s, cache per exact
# (vendor, product, version) so a version shared by many machines (which is
# the common case here) only costs one real call.
_nvd_cache: dict = {}


def nvd_check(vendor: str, product: str, version: str) -> dict:
    """
    Vendor-neutral CVE lookup via NVD (official NIST database), matched
    server side against the exact version using their CPE range data
    (versionStartIncluding/versionEndExcluding), not a text search. Works
    for anything with an NVD CPE entry regardless of how it's installed,
    unlike OSV's Debian/Ubuntu ecosystem data this also covers Bitnami/
    bundled software (verified: correctly returns 0 for PHP 8.2.33, 16 for
    PHP 8.2.28, matching what OSV + manual php.net changelog checking found).
    """
    cache_key = (vendor, product, version)
    if cache_key in _nvd_cache:
        return _nvd_cache[cache_key]

    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString={cpe}&resultsPerPage=50"
    data = http_get(url, headers=NVD_HEADERS)
    time.sleep(2)  # stay well under the anonymous rate limit (~5 req/30s)

    if data is None:
        result = {"status": "lookup_failed"}
    else:
        vulns = data.get("vulnerabilities", [])
        items = []
        for entry in vulns:
            cve = entry.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_score, cvss_vector = None, None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    cvss_data = metrics[key][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break
            summary = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            items.append({
                "id": cve.get("id"),
                "summary": summary[:220],
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
            })
        result = {
            "status": "ok",
            "count": len(vulns),
            "items": items,
            "note": "NVD (official NIST database), matched server side against the exact "
                    "version, works regardless of how the software was installed.",
        }

    _nvd_cache[cache_key] = result
    return result


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
    # WPScan's /wordpresses/{version} endpoint wants the version with dots
    # stripped (5.6.1 -> 561, per their own OpenAPI spec), not the literal
    # dotted version, a bare dotted version silently matches nothing.
    url_version = wp_version.replace(".", "")
    data = http_get(
        f"https://wpscan.com/api/v3/wordpresses/{url_version}",
        headers={"Authorization": f"Token token={WPSCAN_API_TOKEN}"},
    )
    if data is None:
        return {"status": "lookup_failed"}
    key = next(iter(data), None)
    vulns = data.get(key, {}).get("vulnerabilities", []) if key else []
    items = []
    for v in vulns:
        cvss = v.get("cvss") or {}
        items.append({
            "id": v.get("id"),
            "summary": (v.get("title") or "")[:220],
            "cvss_score": cvss.get("score"),
            "cvss_vector": cvss.get("vector"),
            "fixed_in": v.get("fixed_in"),
        })
    return {
        "status": "ok",
        "count": len(vulns),
        "titles": [v.get("title") for v in vulns],
        "items": items,
    }


def enrich_record(record: dict, targets: dict) -> dict:
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
    is_bitnami = record["kind"] == "lightsail"
    ecosystem_info = os_to_ecosystem(record.get("os", "")) if is_os_packaged else None
    dpkg_versions = record.get("dpkg_versions", {})
    bitnami_versions = record.get("bitnami_versions", {})

    php_finding = None
    php_match = re.search(r"PHP\s+([\d.]+)", record.get("php", ""))
    if php_match:
        php_version = php_match.group(1)
        php_finding = {"component": "php", "version": php_version, "eol": eol_check("php", php_version)}
        # NVD is used for PHP specifically instead of OSV: it's vendor
        # neutral (matches on the official php:php CPE, not a distro
        # package), so it covers Bitnami/Lightsail's bundled PHP too, which
        # OSV's Debian/Ubuntu ecosystem data structurally cannot (Bitnami
        # isn't apt/dpkg managed at all). Cross-validated against OSV and
        # against php.net's own changelog before relying on it: agrees PHP
        # 8.2.33 has 0 current CVEs and 8.2.28 has real ones fixed in 8.2.29/
        # 8.2.30 (CVE-2025-1735, -6491, -1220, -14180, -14177, among others).
        php_finding["nvd"] = nvd_check("php", "php", php_version)
        if is_bitnami:
            # OSV also has a "Bitnami" ecosystem, its own vulndb tracking
            # Bitnami-packaged component versions directly (verified: clean
            # CVSS + fixed-version data, not the open-ended noise seen on
            # Debian). The full manifest version (with Bitnami's own build
            # suffix, e.g. "8.2.28-11") matches more entries than the bare
            # upstream version, use it when we have it.
            php_finding["osv"] = osv_check_with_manifest("php", "Bitnami", bitnami_versions.get("php"), php_version)
        out["findings"].append(php_finding)

    apache_match = re.search(r"Apache/([\d.]+)", record.get("webserver", ""))
    if apache_match:
        apache_version = apache_match.group(1)
        finding = {"component": "apache", "version": apache_version, "eol": eol_check("apache", apache_version)}
        if ecosystem_info:
            eco, ver = ecosystem_info
            finding["osv"] = osv_check_with_manifest("apache2", f"{eco}:{ver}", dpkg_versions.get("apache2"), apache_version)
        elif is_bitnami:
            finding["osv"] = osv_check_with_manifest("apache", "Bitnami", bitnami_versions.get("apache"), apache_version)
        apache_target = target_for(targets, "apache", record["name"])
        if apache_target:
            finding["policy_target"] = {"target": apache_target, "at_target": apache_version == apache_target}
        out["findings"].append(finding)

    # Two different mysql client output formats seen in the wild: OS-packaged
    # ("mysql  Ver 15.1 Distrib 10.11.18-MariaDB, ...") and Bitnami's bundled
    # client ("... mysql from 11.8.2-MariaDB, client 15.2 ...").
    db_match = re.search(r"(?:Distrib|from)\s+([\d.]+)-MariaDB", record.get("db", ""))
    if db_match:
        db_version = db_match.group(1)
        finding = {"component": "mariadb", "version": db_version, "eol": eol_check("mariadb", db_version)}
        if ecosystem_info:
            eco, ver = ecosystem_info
            major_minor = ".".join(db_version.split(".")[:2])
            manifest = dpkg_versions.get("mariadb-server") or dpkg_versions.get("mysql-server")
            finding["osv"] = osv_check_with_manifest(f"mariadb-{major_minor}", f"{eco}:{ver}", manifest, db_version)
        elif is_bitnami:
            finding["osv"] = osv_check_with_manifest("mariadb", "Bitnami", bitnami_versions.get("mariadb"), db_version)
        mariadb_target = target_for(targets, "mariadb", record["name"])
        if mariadb_target:
            finding["policy_target"] = {"target": mariadb_target, "at_target": db_version == mariadb_target}
        out["findings"].append(finding)

    vhost_routing = parse_vhost_routing(record.get("vhosts", ""))

    for wp in record.get("wp_installs", []):
        wp_version = wp["version"]
        if wp_version in ("", "UNKNOWN"):
            continue
        finding = {
            "component": "wordpress",
            "path": wp["path"],
            "version": wp_version,
            "eol": eol_check("wordpress", wp_version),
            "routing": vhost_routing.get(wp["path"].rstrip("/"), {"domains": [], "catchall": False}),
        }
        if php_match:
            finding["php_compatibility"] = wp_php_compatibility(wp_version, php_match.group(1))
        if is_bitnami:
            # Per install, not the box level manifest version: a Lightsail
            # box is multi tenant, each site's WordPress core can be a
            # different version from the default Bitnami install, the
            # manifest only reflects that default one.
            finding["osv"] = osv_check("wordpress", "Bitnami", wp_version)
        finding["wpscan"] = wpscan_check(wp_version)
        out["findings"].append(finding)

    if php_finding is not None:
        wp_versions = sorted({
            f["version"] for f in out["findings"]
            if f.get("component") == "wordpress" and f.get("version") not in ("", "UNKNOWN")
        })
        php_target = target_for(targets, "php", record["name"])
        if wp_versions:
            php_finding["bump_compatibility"] = check_php_bump_compatibility(
                php_finding["eol"], wp_versions, policy_target=php_target
            )
        if php_target:
            php_finding["policy_target"] = {
                "target": php_target,
                "at_target": php_finding["version"] == php_target,
            }

    return out


def parse_vhost_routing(vhosts_text: str) -> dict:
    """
    Parses the Apache vhost dump collected by aws_version_audit.py (blocks of
    "-- <file> --" followed by grep'd ServerName/ServerAlias/DocumentRoot
    lines) into {normalized_document_root: {"domains": [...], "catchall": bool}}.

    Apache config is the ground truth for what's actually served, not the
    presence of a wp-includes directory, a WordPress install with no vhost
    pointing at it is not reachable over HTTP at all, one behind a wildcard
    ServerAlias * is reachable by any unmatched Host header (including a
    direct IP hit) even without its own domain, which is its own kind of
    exposure worth flagging separately from a dead orphan directory.
    """
    routing: dict = {}
    current_domains: list = []
    current_docroot = None

    def flush():
        nonlocal current_domains, current_docroot
        if current_docroot:
            entry = routing.setdefault(current_docroot, {"domains": set(), "catchall": False})
            for d in current_domains:
                if d == "*":
                    entry["catchall"] = True
                else:
                    entry["domains"].add(d)
        current_domains = []
        current_docroot = None

    for line in vhosts_text.splitlines():
        line = line.strip()
        if line.startswith("-- ") and line.endswith(" --"):
            flush()
            continue
        m = re.match(r"(?:ServerName|ServerAlias)\s+(.+)", line)
        if m:
            current_domains.extend(m.group(1).split())
            continue
        m = re.match(r'DocumentRoot\s+"?([^"]+?)"?\s*$', line)
        if m:
            current_docroot = m.group(1).rstrip("/")
    flush()

    return {path: {"domains": sorted(v["domains"]), "catchall": v["catchall"]} for path, v in routing.items()}


def check_php_bump_compatibility(php_eol: dict, wp_versions: list, policy_target: str | None = None) -> dict:
    """
    For a PHP finding, checks whether bumping to the same-cycle patch target,
    to the next-cycle recommended target, and to a declared policy target
    (targets.json, e.g. "we're moving the whole fleet to 8.5") stays
    compatible with every WordPress install found on that same machine (a
    Lightsail box can run several sites sharing one PHP runtime, bumping PHP
    affects all of them).
    """
    candidate_targets = {
        "same_cycle": php_eol.get("latest_in_cycle"),
        "next_cycle": php_eol.get("recommended_target_version"),
        "policy": policy_target,
    }
    result = {}
    for label, target_version in candidate_targets.items():
        if not target_version:
            continue
        incompatible_with = []
        unknown_for = []
        for wp_version in wp_versions:
            compat = wp_php_compatibility(wp_version, target_version)
            if compat.get("status") == "incompatible":
                incompatible_with.append(wp_version)
            elif compat.get("status") == "unknown":
                unknown_for.append(wp_version)
        result[label] = {
            "target": target_version,
            "safe": not incompatible_with,
            "incompatible_with": incompatible_with,
            "unknown_for": unknown_for,
        }
    return result


def print_summary(enriched: list) -> None:
    print("\n" + "=" * 100)
    for rec in enriched:
        flagged = [
            f for f in rec["findings"]
            if f.get("eol", {}).get("status") in ("eol", "security_only")
            or f.get("eol", {}).get("outdated_patch")
            or f.get("eol", {}).get("soon_eol")
            or f.get("php_compatibility", {}).get("status") == "incompatible"
            or f.get("osv", {}).get("count", 0) > 0
        ]
        if not flagged:
            continue
        print(f"[{rec['account_label']}] {rec['name']} ({rec['public_ip']})")
        for f in flagged:
            bits = [f"  - {f['component']} {f.get('version', '')}"]
            eol = f.get("eol", {})
            if eol.get("outdated_patch"):
                bits.append(f"newer patch available in cycle: {eol.get('latest_in_cycle')}")
            if eol.get("status") == "eol":
                bits.append(f"EOL since {eol.get('eol_date')} (URGENT), bump to {eol.get('recommended_target')}")
            elif eol.get("status") == "security_only":
                bits.append(
                    f"active support ended {eol.get('support_until')}, still gets security "
                    f"patches until {eol.get('eol_date')}, plan a bump but not urgent"
                )
            elif eol.get("soon_eol"):
                bits.append(
                    f"EOL approaching in {eol.get('days_to_eol')} days ({eol.get('eol_date')}), "
                    f"plan a bump to {eol.get('recommended_target')}"
                )
            compat = f.get("php_compatibility", {})
            if compat.get("status") == "incompatible":
                bits.append(f"PHP incompatible (WP needs {compat.get('wp_supported_php_range')})")
            osv = f.get("osv", {})
            if osv.get("count", 0) > 0:
                bits.append(f"OSV: {osv['count']} potential CVEs (rough signal)")
            print(", ".join(bits))
    print("=" * 100)


def print_policy_summary(enriched: list, targets: dict) -> None:
    php_target = targets.get("php")
    if not php_target:
        return
    print(f"\n=== PHP target {php_target}: fleet compatibility ===")
    compatible, blocked, no_wp = [], [], []
    for rec in enriched:
        php_findings = [f for f in rec["findings"] if f.get("component") == "php"]
        if not php_findings:
            continue
        policy = php_findings[0].get("bump_compatibility", {}).get("policy")
        if policy is None:
            no_wp.append(rec["name"])
        elif policy["safe"]:
            compatible.append(rec["name"])
        else:
            blocked.append((rec["name"], policy["incompatible_with"]))

    print(f"compatible now: {len(compatible)} -> {', '.join(compatible) or '-'}")
    if blocked:
        print(f"blocked: {len(blocked)}")
        for name, wp_versions in blocked:
            print(f"  - {name}: needs WordPress bump first ({', '.join(wp_versions)} incompatible with PHP {php_target})")
    if no_wp:
        print(f"no WordPress installs to check against (custom app or empty): {', '.join(no_wp)}")


def main() -> None:
    global WPSCAN_API_TOKEN
    import os
    WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN")

    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    if not input_path.exists():
        print(f"no input at {input_path}, run aws_version_audit.py first", file=sys.stderr)
        sys.exit(1)

    records = json.loads(input_path.read_text())

    exclusions = load_exclusions()
    if exclusions:
        skipped = [r["name"] for r in records if r["name"] in exclusions]
        records = [r for r in records if r["name"] not in exclusions]
        for name in skipped:
            print(f"excluded: {name} ({exclusions[name]})")

    targets = load_targets()
    if targets.get("php") or targets.get("apache") or targets.get("mariadb"):
        print(f"declared targets: php={targets.get('php')} apache={targets.get('apache')} mariadb={targets.get('mariadb')}")

    enriched = [enrich_record(r, targets) for r in records]

    print_summary(enriched)
    print_policy_summary(enriched, targets)

    DEFAULT_OUTPUT.parent.mkdir(exist_ok=True)
    DEFAULT_OUTPUT.write_text(json.dumps(enriched, indent=2))
    print(f"\nwrote {DEFAULT_OUTPUT}")


if __name__ == "__main__":
    main()
