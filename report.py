#!/usr/bin/env python3
"""
Turns vuln_report.json into a single self contained HTML file built around
one question: what needs patching right now.

Default view is a flat patch list, one row per finding that actually needs
attention (OK/info items hidden by default, toggle to see everything), sorted
worst first, with an explicit Action column instead of prose. A secondary
"by machine" grouped view is available for full detail on one box.

No dependencies, no build step, no external JS framework. Python precomputes
severity and the action text for every finding, embeds it as a JSON blob,
a small vanilla JS snippet only filters/sorts/renders that array, it never
recomputes anything.

Usage:
    python3 report.py [path/to/vuln_report.json] [path/to/output.html]
"""

import html
import json
import sys
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
DEFAULT_INPUT = SCRIPT_DIR / "output" / "vuln_report.json"
DEFAULT_OUTPUT = SCRIPT_DIR / "output" / "report.html"



CATEGORY_COLOR = {
    "CVE": "#c0392b",
    "EOL": "#7d3c98",
    "INCOMPATIBLE": "#d68910",
    "UNREACHABLE": "#5d6d7e",
    "TARGET": "#884ea0",
    "OK": "#1e8449",
}
# Order used to pick the primary badge color when a finding has several
# categories at once (e.g. EOL + CVE), worst first.
CATEGORY_PRIORITY = ["CVE", "EOL", "INCOMPATIBLE", "UNREACHABLE", "TARGET", "OK"]


def finding_categories(f: dict) -> list:
    """CVE / EOL / INCOMPATIBLE / UNREACHABLE / TARGET / OK, combinable, e.g.
    a fully dead version with tracked CVEs against it shows as EOL + CVE, not
    just one or the other. "Not reachable over HTTP" for a WordPress install
    is handled by the separate Routing filter/tag, not duplicated here."""
    if f.get("component") == "instance":
        return ["UNREACHABLE"]

    cats = []
    if f.get("eol", {}).get("status") == "eol":
        cats.append("EOL")
    # OSV's Debian/Ubuntu data drove false positives at first (queried with
    # the bare upstream version, e.g. "2.4.68", which dpkg version comparison
    # reads as OLDER than the real package "2.4.68-1~deb12u1", so already
    # fixed CVEs looked open) and Debian-dismissed ("unimportant" urgency,
    # never gets a "fixed" event, so it reads as affecting every version
    # forever) entries. Both are fixed at the source now (vuln_lookup.py
    # queries with the real dpkg version and filters dismissed entries), so
    # this is trusted again, same status as WPScan.
    if f.get("osv", {}).get("count", 0) > 0 or f.get("wpscan", {}).get("count", 0) > 0 or f.get("nvd", {}).get("count", 0) > 0:
        cats.append("CVE")
    if f.get("php_compatibility", {}).get("status") == "incompatible":
        cats.append("INCOMPATIBLE")
    policy = f.get("policy_target")
    if policy and not policy.get("at_target"):
        cats.append("TARGET")
    return cats or ["OK"]


ALL_CATEGORIES = ["CVE", "EOL", "INCOMPATIBLE", "UNREACHABLE", "TARGET", "OK"]
DEFAULT_HIDDEN_CATEGORIES = {"OK"}


def category_rank(cats: list) -> int:
    """Numeric rank for sorting and the left-border color class only, the
    actual filtering/visibility is category based, not this."""
    if ("CVE" in cats and "EOL" in cats) or "INCOMPATIBLE" in cats:
        return 0
    if "CVE" in cats or "EOL" in cats:
        return 1
    if "UNREACHABLE" in cats or "TARGET" in cats:
        return 2
    return 4


def is_routed(f: dict) -> bool:
    """False only for a WordPress install with zero vhost pointing at it,
    Apache config never serves it, not reachable over HTTP at all."""
    if f.get("component") != "wordpress":
        return True
    routing = f.get("routing", {})
    return bool(routing.get("domains")) or bool(routing.get("catchall"))


ROUTING_LABEL = {
    "served": "Served (real domain)",
    "catchall": "Catch-all only (no real domain)",
    "orphan": "Orphan (not routed at all)",
    "n/a": "N/A (not a WordPress finding)",
}

# Only "served" and "n/a" shown by default: catch-all and orphan installs
# are disk debt, not something actually reachable at a client domain,
# noisy to mix into a "what needs patching" view unless asked for.
DEFAULT_HIDDEN_ROUTING = {"catchall", "orphan"}


def routing_status(f: dict) -> str:
    if f.get("component") != "wordpress":
        return "n/a"
    routing = f.get("routing", {})
    real_domains = [d for d in routing.get("domains", []) if d != "www.example.com"]
    if real_domains:
        return "served"
    if routing.get("catchall"):
        return "catchall"
    return "orphan"


def finding_severity(f: dict) -> int:
    """Numeric rank, used only for the left-border color class and sorting.
    Actual visibility/filtering is category based (see finding_categories)."""
    return category_rank(finding_categories(f))


def bump_compat_note(compat: dict) -> str:
    if compat.get("safe"):
        return "safe with current WordPress"
    bad = ", ".join(compat.get("incompatible_with", []))
    return f"WARNING: incompatible with WordPress {bad} on this machine, upgrade WP first or it will break"


def finding_tags(f: dict) -> list:
    """Compact badges for a row: what kind of thing this is, at a glance,
    separate from the Action sentence which stays a plain instruction."""
    tags = []

    if f.get("component") == "wordpress":
        routing = f.get("routing", {})
        real_domains = [d for d in routing.get("domains", []) if d != "www.example.com"]
        if routing.get("catchall"):
            tags.append({
                "text": "catch-all", "color": "#b7950b",
                "title": "Exposed via wildcard ServerAlias *, reachable by any unmatched Host header incl. direct IP, no dedicated domain",
            })
        elif real_domains:
            title = ", ".join(real_domains)
            text = real_domains[0] if len(real_domains) == 1 else f"{len(real_domains)} domains"
            tags.append({"text": f"served: {html.escape(text)}", "color": "#1e8449", "title": html.escape(title)})
        else:
            tags.append({"text": "orphan", "color": "#7d6608", "title": "Not routed by any vhost, not reachable over HTTP, cleanup candidate"})

    if f.get("eol", {}).get("outdated_patch"):
        tags.append({"text": "patch available", "color": "#2874a6", "title": f"Newer release in the same cycle: {f['eol'].get('latest_in_cycle')}"})

    policy = f.get("policy_target")
    if policy and not policy.get("at_target"):
        tags.append({"text": f"target: {html.escape(str(policy['target']))}", "color": "#884ea0", "title": "Declared fleet target not reached yet"})

    return tags


def primary_category_color(cats: list) -> str:
    for c in CATEGORY_PRIORITY:
        if c in cats:
            return CATEGORY_COLOR[c]
    return CATEGORY_COLOR["OK"]


def render_category_badges(cats: list, extra_class: str = "") -> str:
    spans = "".join(
        f'<span class="badge {extra_class}" style="background:{CATEGORY_COLOR.get(c, "#888")}">{c}</span>'
        for c in cats
    )
    return f'<span class="badge-group">{spans}</span>'


def cvss_badge(score, vector, qualitative=None) -> str:
    if score is not None:
        color = "#7b241c" if score >= 9 else "#c0392b" if score >= 7 else "#d68910" if score >= 4 else "#7d6608"
        text = f"CVSS {score}"
        title = html.escape(vector or "")
    elif qualitative:
        color = {"critical": "#7b241c", "high": "#c0392b", "medium": "#d68910", "low": "#7d6608"}.get(qualitative.lower(), "#888")
        text = qualitative.upper()
        title = "qualitative severity, no CVSS vector available"
    else:
        color, text, title = "#888", "n/a", "no severity data available"
    return f'<span class="cvss-badge" style="background:{color}" title="{title}">{text}</span>'


def render_cve_items(f: dict) -> str:
    """NVD items (PHP, vendor neutral, covers Bitnami too) plus OSV items
    (queried with the real dpkg package version, Debian "unimportant"
    dismissed entries excluded, see vuln_lookup.py) plus WPScan items when
    available. All three give an id, a CVSS badge when known, and a link to
    the source."""
    rows = []

    nvd = f.get("nvd", {})
    for it in nvd.get("items", []):
        badge = cvss_badge(it.get("cvss_score"), it.get("cvss_vector"))
        summary = html.escape(str(it.get("summary", "")))
        link = f'https://nvd.nist.gov/vuln/detail/{it["id"]}'
        rows.append(f'<li>{badge} <a href="{html.escape(link)}" target="_blank" rel="noopener">{html.escape(str(it["id"]))}</a><div class="cve-summary">{summary}</div></li>')

    osv = f.get("osv", {})
    for it in osv.get("items", []):
        badge = cvss_badge(it.get("cvss_score"), it.get("cvss_vector"), it.get("qualitative"))
        summary = html.escape(str(it.get("summary", "")))
        link = f'https://osv.dev/vulnerability/{it["id"]}'
        rows.append(f'<li>{badge} <a href="{html.escape(link)}" target="_blank" rel="noopener">{html.escape(it["id"])}</a><div class="cve-summary">{summary}</div></li>')

    wpscan = f.get("wpscan", {})
    for it in wpscan.get("items", []):
        badge = cvss_badge(it.get("cvss_score"), it.get("cvss_vector"))
        fixed = f' <span class="cve-fixed">fixed in {html.escape(str(it["fixed_in"]))}</span>' if it.get("fixed_in") else ""
        summary = html.escape(str(it.get("summary", "")))
        link_open = f'<a href="https://wpscan.com/vulnerability/{it["id"]}" target="_blank" rel="noopener">' if it.get("id") else ""
        link_close = "</a>" if it.get("id") else ""
        rows.append(f'<li>{badge}{fixed}{link_open}<div class="cve-summary">{summary}</div>{link_close}</li>')

    if not rows:
        return ""

    extra_bits = []
    if osv.get("count", 0) > len(osv.get("items", [])):
        extra_bits.append(f'+ {osv["count"] - len(osv.get("items", []))} more OSV entries not fetched in detail')
    extra = f'<p class="cve-caveat">{"; ".join(extra_bits)}</p>' if extra_bits else ""
    notes = [n for n in (nvd.get("note", ""), osv.get("note", "")) if n]
    note_html = "".join(f'<p class="cve-caveat">{html.escape(n)}</p>' for n in notes)
    return f'<ul class="cve-list">{"".join(rows)}</ul>{extra}{note_html}'


def render_wp_context(f: dict) -> str:
    if f.get("component") != "wordpress":
        return ""
    routing = f.get("routing", {})
    real_domains = [d for d in routing.get("domains", []) if d != "www.example.com"]
    parts = []
    if routing.get("catchall"):
        parts.append(
            "<p><strong>Catch-all vhost</strong> (ServerAlias *), reachable by any unmatched "
            "Host header including a direct IP hit, no dedicated domain owns this install.</p>"
        )
    if real_domains:
        items = "".join(f"<li>{html.escape(d)}</li>" for d in real_domains)
        parts.append(f'<p><strong>Domains served ({len(real_domains)})</strong></p><ul class="domain-list">{items}</ul>')
    if not real_domains and not routing.get("catchall"):
        parts.append(
            "<p><strong>Not routed</strong> by any Apache vhost, not reachable over HTTP at all, "
            "cleanup candidate once confirmed unused.</p>"
        )
    compat = f.get("php_compatibility", {})
    if compat.get("status"):
        parts.append(
            f'<p>PHP compatibility range for this WordPress core: '
            f'<code>{html.escape(str(compat.get("wp_supported_php_range", "?")))}</code> '
            f'(currently: {html.escape(compat["status"])})</p>'
        )
    return "".join(parts)


def render_bump_compat(f: dict) -> str:
    bc = f.get("bump_compatibility")
    if not bc:
        return ""
    labels = {"same_cycle": "Same cycle", "next_cycle": "Next cycle (auto-recommended)", "policy": "Declared fleet target"}
    items = []
    for key, label in labels.items():
        c = bc.get(key)
        if not c:
            continue
        status = "safe" if c["safe"] else f'blocked by WordPress {", ".join(c["incompatible_with"])}'
        items.append(f"<li>{label} &rarr; {html.escape(str(c['target']))}: {html.escape(status)}</li>")
    if not items:
        return ""
    return f'<p><strong>Bump compatibility</strong></p><ul class="bump-list">{"".join(items)}</ul>'


def render_detail_panel(f: dict) -> str:
    parts = []
    if "CVE" in finding_categories(f):
        parts.append(render_cve_items(f))
    parts.append(render_wp_context(f))
    if f.get("component") == "php":
        parts.append(render_bump_compat(f))

    eol = f.get("eol", {})
    meta_bits = []
    if eol.get("cycle"):
        meta_bits.append(f"cycle {html.escape(str(eol['cycle']))}")
    if eol.get("eol_date"):
        meta_bits.append(f"EOL date {html.escape(str(eol['eol_date']))}")
    if eol.get("support_until"):
        meta_bits.append(f"active support ended {html.escape(str(eol['support_until']))}")
    if meta_bits:
        parts.append(f'<p class="eol-meta">{" &middot; ".join(meta_bits)}</p>')

    content = "".join(p for p in parts if p)
    return content or '<p class="empty-detail">Nothing more to show for this finding.</p>'


def render_finding_badge(f: dict, extra_class: str = "") -> str:
    return render_category_badges(finding_categories(f), extra_class)


def render_tags(tags: list) -> str:
    if not tags:
        return ""
    pills = "".join(
        f'<span class="tag" style="background:{t["color"]}" title="{t["title"]}">{t["text"]}</span>'
        for t in tags
    )
    return f'<div class="tags">{pills}</div>'


def finding_action(f: dict) -> str:
    """One short, explicit sentence: what to actually do about this finding.

    outdated_patch (a same-cycle bump, e.g. 8.2.10 -> 8.2.33) and the cycle's
    own EOL status are independent, a finding can need both: bump within
    cycle now to clear known CVEs, and still plan the bigger cycle move later.
    Routing/target context lives in tags (see finding_tags), not here.
    """
    if f.get("component") == "instance":
        return html.escape(f.get("note", "investigate"))

    eol = f.get("eol", {})
    parts = []

    policy = f.get("policy_target")
    has_declared_target = bool(policy and not policy.get("at_target"))
    if has_declared_target:
        policy_compat = f.get("bump_compatibility", {}).get("policy")
        note = f" ({html.escape(bump_compat_note(policy_compat))})" if policy_compat else ""
        parts.append(f"Bump to {html.escape(str(policy['target']))} (declared fleet target){note}")

    if eol.get("status") == "eol":
        parts.append(f"Bump to {html.escape(str(eol.get('recommended_target')))} (EOL since {html.escape(str(eol.get('eol_date')))})")
        return ", ".join(parts)

    bump_compat = f.get("bump_compatibility", {})

    if eol.get("outdated_patch"):
        note = f" ({html.escape(bump_compat_note(bump_compat.get('same_cycle')))})" if bump_compat.get("same_cycle") else ""
        parts.append(
            f"Bump to {html.escape(str(eol.get('latest_in_cycle')))} now (clears known issues "
            f"in current {html.escape(str(f.get('version', '')))}){note}"
        )

    # A declared target already says "bump to X", the generic EOL-driven
    # "plan a move" advice below would just repeat the same thing with the
    # same compat warning, skip it once there's an explicit decision.
    if has_declared_target:
        pass
    elif eol.get("status") == "security_only":
        note = f" ({html.escape(bump_compat_note(bump_compat.get('next_cycle')))})" if bump_compat.get("next_cycle") else ""
        parts.append(
            f"then plan a move to {html.escape(str(eol.get('recommended_target')))} "
            f"(active support ended {html.escape(str(eol.get('support_until')))}, "
            f"security patches only until {html.escape(str(eol.get('eol_date')))}){note}"
        )
    elif eol.get("soon_eol"):
        note = f" ({html.escape(bump_compat_note(bump_compat.get('next_cycle')))})" if bump_compat.get("next_cycle") else ""
        parts.append(
            f"then plan a move to {html.escape(str(eol.get('recommended_target')))} "
            f"(cycle EOL in {eol.get('days_to_eol')} days, {html.escape(str(eol.get('eol_date')))}){note}"
        )

    compat = f.get("php_compatibility", {})
    if compat.get("status") == "incompatible":
        parts.append(
            f"fix PHP/WordPress mismatch, WP needs PHP {html.escape(str(compat.get('wp_supported_php_range')))}"
        )

    if parts:
        return ", ".join(parts)

    osv = f.get("osv", {})
    if osv.get("count", 0) > 0:
        return f"Review {osv['count']} potential CVEs (rough signal, not confirmed)"

    return "No action"


def checkbox_group(name: str, values: list, css_class: str, default_checked=lambda v: True) -> str:
    items = "".join(
        f'<label><input type="checkbox" class="{css_class}" value="{html.escape(str(v))}" '
        f'{"checked" if default_checked(v) else ""}> {html.escape(str(label))}</label>'
        for v, label in values
    )
    return f'<div class="filter-group"><span class="filter-title">{html.escape(name)}</span>{items}</div>'


def render_patch_row(rec: dict, f: dict) -> str:
    sev = finding_severity(f)
    name = html.escape(rec["name"])
    account = html.escape(rec["account_label"])
    ip = html.escape(rec.get("public_ip") or "no public ip")
    comp = html.escape(f.get("component", ""))
    version = html.escape(str(f.get("version", "")))
    path = f.get("path")
    path_html = f'<div class="row-path">{html.escape(path)}</div>' if path else ""
    action = finding_action(f)
    tags_html = render_tags(finding_tags(f))
    badge_html = render_finding_badge(f)
    detail_html = render_detail_panel(f)

    return f"""
    <tr class="sev-{sev} clickable-row" onclick="this.nextElementSibling.classList.toggle('open')">
      <td>{badge_html}</td>
      <td><div class="row-vm">{name}</div><div class="row-meta">{account} &middot; {ip}</div></td>
      <td><span class="comp">{comp}</span><div class="version">{version}</div>{path_html}{tags_html}</td>
      <td class="action-cell">{action}</td>
    </tr>
    <tr class="detail-row"><td colspan="4"><div class="detail-panel">{detail_html}</div></td></tr>
    """


def render_finding(f: dict) -> str:
    comp = html.escape(f.get("component", ""))
    version = html.escape(str(f.get("version", "")))
    path = f.get("path")
    sev = finding_severity(f)
    action = finding_action(f)
    path_html = f'<div class="path">{html.escape(path)}</div>' if path else ""
    tags_html = render_tags(finding_tags(f))
    badge_html = render_finding_badge(f)
    detail_html = render_detail_panel(f)

    return f"""
    <details class="finding sev-{sev}">
      <summary class="finding-head">
        {badge_html}
        <span class="comp">{comp}</span>
        <span class="version">{version}</span>
      </summary>
      {path_html}
      {tags_html}
      <div class="detail">{action}</div>
      <div class="detail-panel">{detail_html}</div>
    </details>
    """


def render_vm_html(rec: dict, sev: int) -> str:
    name = html.escape(rec["name"])
    account = html.escape(rec["account_label"])
    ip = html.escape(rec.get("public_ip") or "no public ip")
    kind = html.escape(rec.get("kind", ""))

    findings = rec.get("findings", [])
    vm_cats = sorted({c for f in findings for c in finding_categories(f) if c != "OK"}, key=CATEGORY_PRIORITY.index) or ["OK"]
    badge_html = render_category_badges(vm_cats, extra_class="big")

    findings_html = "".join(render_finding(f) for f in findings) or (
        "<div class='finding sev-4'><em>nothing to report</em></div>"
    )

    return f"""
    <div class="vm-card sev-{sev}">
      <div class="vm-head">
        {badge_html}
        <span class="vm-name">{name}</span>
        <span class="vm-meta">{account} &middot; {kind} &middot; {ip}</span>
      </div>
      <div class="findings">{findings_html}</div>
    </div>
    """


def build_html(records: list, source_path: Path) -> str:
    vm_views = []
    patch_rows = []
    for rec in records:
        findings = rec.get("findings", [])
        vm_cats = sorted({c for f in findings for c in finding_categories(f) if c != "OK"}, key=CATEGORY_PRIORITY.index) or ["OK"]
        sev = min((finding_severity(f) for f in findings), default=4)
        components = sorted({f.get("component", "") for f in findings})
        vm_views.append({
            "name": rec["name"],
            "account": rec["account_label"],
            "kind": rec.get("kind", ""),
            "sev": sev,
            "categories": vm_cats,
            "components": components,
            "html": render_vm_html(rec, sev),
        })
        for f in findings:
            patch_rows.append({
                "name": rec["name"],
                "account": rec["account_label"],
                "kind": rec.get("kind", ""),
                "component": f.get("component", ""),
                "routing": routing_status(f),
                "categories": finding_categories(f),
                "sev": finding_severity(f),
                "html": render_patch_row(rec, f),
            })

    kinds = sorted({v["kind"] for v in vm_views})
    accounts = sorted({v["account"] for v in vm_views})
    components_present = sorted({c for v in vm_views for c in v["components"] if c})

    counts = {c: 0 for c in ALL_CATEGORIES}
    for r in patch_rows:
        for c in r["categories"]:
            counts[c] += 1
    summary_html = "".join(
        f'<div class="summary-item"><span class="count" style="color:{CATEGORY_COLOR[c]}">'
        f'{counts[c]}</span><span class="label">{c}</span></div>'
        for c in ALL_CATEGORIES
    )

    kind_filters = checkbox_group("Type", [(k, k) for k in kinds], "filter-kind")
    account_filters = checkbox_group("Account", [(a, a) for a in accounts], "filter-account")
    status_filters = checkbox_group(
        "Category", [(c, c) for c in ALL_CATEGORIES], "filter-cat",
        default_checked=lambda c: c not in DEFAULT_HIDDEN_CATEGORIES,
    )
    component_filters = checkbox_group(
        "Component", [(c, c) for c in components_present], "filter-component"
    )
    routing_filters = checkbox_group(
        "Routing", [(k, ROUTING_LABEL[k]) for k in ("served", "catchall", "orphan", "n/a")], "filter-routing",
        default_checked=lambda k: k not in DEFAULT_HIDDEN_ROUTING,
    )

    rows_json = json.dumps(patch_rows)
    data_json = json.dumps(vm_views)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AWS version audit report</title>
<style>
  :root {{ color-scheme: light; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #f5f6f7;
    color: #1c1c1e;
    margin: 0;
    padding: 24px;
  }}
  h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
  .meta {{ color: #6b6b70; font-size: 0.85rem; margin-bottom: 20px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
  .summary-item {{
    background: white;
    border-radius: 10px;
    padding: 12px 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 80px;
  }}
  .summary-item .count {{ font-size: 1.6rem; font-weight: 700; }}
  .summary-item .label {{ font-size: 0.75rem; color: #6b6b70; text-transform: uppercase; }}
  .controls {{
    background: white;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    padding: 14px 18px;
    margin-bottom: 20px;
    display: flex;
    gap: 28px;
    flex-wrap: wrap;
    align-items: flex-start;
  }}
  .filter-group {{ display: flex; flex-direction: column; gap: 4px; }}
  .filter-title {{
    font-size: 0.72rem;
    text-transform: uppercase;
    color: #6b6b70;
    font-weight: 700;
    margin-bottom: 2px;
  }}
  .filter-group label {{ font-size: 0.85rem; display: flex; align-items: center; gap: 6px; }}
  .view-group, .sort-group {{ display: flex; flex-direction: column; gap: 4px; }}
  .sort-group {{ margin-left: auto; }}
  select {{ font-size: 0.85rem; padding: 4px 6px; border-radius: 6px; border: 1px solid #ddd; }}
  #result-count {{ font-size: 0.78rem; color: #6b6b70; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; }}
  thead th {{
    text-align: left;
    font-size: 0.72rem;
    text-transform: uppercase;
    color: #6b6b70;
    padding: 10px 12px;
    border-bottom: 2px solid #eee;
  }}
  tbody tr {{ border-left: 5px solid #ccc; box-shadow: 0 1px 0 #eee; }}
  tbody tr.sev-0 {{ border-left-color: #c0392b; }}
  tbody tr.sev-1 {{ border-left-color: #d68910; }}
  tbody tr.sev-2 {{ border-left-color: #b7950b; }}
  tbody tr.sev-3 {{ border-left-color: #7d6608; }}
  tbody tr.sev-4 {{ border-left-color: #1e8449; }}
  tbody td {{ padding: 10px 12px; font-size: 0.85rem; vertical-align: top; }}
  .action-cell {{ font-weight: 500; }}
  .row-vm {{ font-weight: 600; }}
  .row-meta {{ color: #6b6b70; font-size: 0.78rem; }}
  .row-path {{ color: #6b6b70; font-size: 0.75rem; font-family: ui-monospace, monospace; }}
  .tags {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }}
  .tag {{
    display: inline-block;
    color: white;
    font-size: 0.68rem;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 10px;
    white-space: nowrap;
    cursor: default;
  }}
  .vm-card {{
    background: white;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    margin-bottom: 14px;
    overflow: hidden;
    border-left: 5px solid #ccc;
  }}
  .vm-card.sev-0 {{ border-left-color: #c0392b; }}
  .vm-card.sev-1 {{ border-left-color: #d68910; }}
  .vm-card.sev-2 {{ border-left-color: #b7950b; }}
  .vm-card.sev-3 {{ border-left-color: #7d6608; }}
  .vm-card.sev-4 {{ border-left-color: #1e8449; }}
  .vm-head {{
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    border-bottom: 1px solid #eee;
  }}
  .vm-name {{ font-weight: 600; font-size: 1rem; }}
  .vm-meta {{ color: #6b6b70; font-size: 0.8rem; margin-left: auto; }}
  .badge {{
    color: white;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    padding: 3px 8px;
    border-radius: 6px;
    letter-spacing: 0.02em;
    white-space: nowrap;
  }}
  .badge.big {{ font-size: 0.75rem; padding: 4px 10px; }}
  .badge-group {{ display: inline-flex; gap: 4px; flex-wrap: wrap; }}
  .findings {{ padding: 8px 16px 14px; }}
  .finding {{ padding: 8px 0; border-bottom: 1px dashed #eee; font-size: 0.85rem; }}
  .finding:last-child {{ border-bottom: none; }}
  .finding-head {{ display: flex; align-items: center; gap: 8px; cursor: pointer; list-style: none; }}
  .finding-head::-webkit-details-marker {{ display: none; }}
  .comp {{ font-weight: 600; text-transform: capitalize; }}
  .version {{ color: #6b6b70; font-family: ui-monospace, monospace; }}
  .path {{ color: #6b6b70; font-size: 0.78rem; font-family: ui-monospace, monospace; margin-top: 2px; }}
  .detail {{ color: #444; font-size: 0.82rem; margin-top: 2px; }}
  .empty {{ color: #6b6b70; text-align: center; padding: 30px; }}

  tr.clickable-row {{ cursor: pointer; }}
  tr.clickable-row:hover {{ background: #f9fafb; }}
  tr.detail-row {{ display: none; }}
  tr.detail-row.open {{ display: table-row; }}
  tr.detail-row td {{ background: #fafbfc; padding: 12px 16px; border-bottom: 1px solid #eee; }}
  .detail-panel {{ font-size: 0.82rem; color: #333; }}
  .detail-panel p {{ margin: 6px 0; }}
  .detail-panel strong {{ font-size: 0.78rem; text-transform: uppercase; color: #6b6b70; }}
  .finding .detail-panel {{ margin-top: 6px; }}

  .cve-list {{ margin: 6px 0; padding-left: 18px; }}
  .cve-list li {{ margin-bottom: 6px; }}
  .cve-list a {{ font-family: ui-monospace, monospace; font-size: 0.78rem; color: #2874a6; text-decoration: none; }}
  .cve-list a:hover {{ text-decoration: underline; }}
  .cve-summary {{ color: #444; font-size: 0.8rem; margin-top: 2px; max-width: 640px; }}
  .cve-fixed {{ color: #1e8449; font-size: 0.72rem; font-weight: 600; }}
  .cve-caveat {{ font-size: 0.72rem; color: #6b6b70; font-style: italic; margin: 6px 0 0; max-width: 500px; }}
  .cvss-badge {{
    display: inline-block;
    color: white;
    font-size: 0.68rem;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 8px;
    margin-right: 4px;
  }}
  .domain-list {{ margin: 4px 0; padding-left: 18px; font-size: 0.8rem; columns: 2; }}
  .bump-list {{ margin: 4px 0; padding-left: 18px; font-size: 0.8rem; }}
  .eol-meta {{ color: #6b6b70; font-size: 0.75rem; }}
  .empty-detail {{ color: #6b6b70; font-style: italic; }}
</style>
</head>
<body>
  <h1>AWS version audit report</h1>
  <div class="meta">generated {generated} &middot; source {html.escape(str(source_path))}</div>
  <div class="summary">{summary_html}</div>

  <div class="controls">
    {kind_filters}
    {account_filters}
    {status_filters}
    {component_filters}
    {routing_filters}
    <div class="view-group">
      <span class="filter-title">View</span>
      <select id="view-select">
        <option value="patchlist">Patch list (flat)</option>
        <option value="machine">By machine (grouped)</option>
      </select>
    </div>
    <div class="sort-group">
      <span class="filter-title">Sort by</span>
      <select id="sort-select">
        <option value="severity">Severity (worst first)</option>
        <option value="machine">Machine</option>
        <option value="account">Account</option>
        <option value="component">Component</option>
      </select>
      <span id="result-count"></span>
    </div>
  </div>

  <div id="content"></div>

  <script id="rows" type="application/json">{rows_json}</script>
  <script id="data" type="application/json">{data_json}</script>
  <script>
    const rowData = JSON.parse(document.getElementById('rows').textContent);
    const vmData = JSON.parse(document.getElementById('data').textContent);

    function checkedValues(selector) {{
      return [...document.querySelectorAll(selector)].map(el => el.value);
    }}

    function render() {{
      const kinds = checkedValues('.filter-kind:checked');
      const accounts = checkedValues('.filter-account:checked');
      const cats = checkedValues('.filter-cat:checked');
      const components = checkedValues('.filter-component:checked');
      const routings = checkedValues('.filter-routing:checked');
      const view = document.getElementById('view-select').value;
      const sortKey = document.getElementById('sort-select').value;
      const content = document.getElementById('content');

      if (view === 'machine') {{
        let filtered = vmData.filter(v =>
          kinds.includes(v.kind) && accounts.includes(v.account)
          && v.categories.some(c => cats.includes(c))
          && v.components.some(c => components.includes(c))
        );
        if (sortKey === 'machine') {{
          filtered.sort((a, b) => a.name.localeCompare(b.name));
        }} else if (sortKey === 'account') {{
          filtered.sort((a, b) => a.account.localeCompare(b.account) || a.sev - b.sev);
        }} else {{
          filtered.sort((a, b) => a.sev - b.sev || a.name.localeCompare(b.name));
        }}
        content.innerHTML = filtered.map(v => v.html).join('') || '<p class="empty">no match</p>';
        document.getElementById('result-count').textContent =
          filtered.length + ' / ' + vmData.length + ' machines shown';
        return;
      }}

      let rows = rowData.filter(r =>
        kinds.includes(r.kind) && accounts.includes(r.account)
        && r.categories.some(c => cats.includes(c)) && components.includes(r.component)
        && routings.includes(r.routing)
      );
      if (sortKey === 'machine') {{
        rows.sort((a, b) => a.name.localeCompare(b.name) || a.sev - b.sev);
      }} else if (sortKey === 'account') {{
        rows.sort((a, b) => a.account.localeCompare(b.account) || a.sev - b.sev);
      }} else if (sortKey === 'component') {{
        rows.sort((a, b) => a.component.localeCompare(b.component) || a.sev - b.sev);
      }} else {{
        rows.sort((a, b) => a.sev - b.sev || a.name.localeCompare(b.name));
      }}

      const tableHtml = rows.length
        ? `<table><thead><tr><th>Category</th><th>Machine</th><th>Component</th><th>Action</th></tr></thead>` +
          `<tbody>${{rows.map(r => r.html).join('')}}</tbody></table>`
        : '<p class="empty">no match</p>';
      content.innerHTML = tableHtml;
      document.getElementById('result-count').textContent =
        rows.length + ' / ' + rowData.length + ' findings shown';
    }}

    document.querySelectorAll('.filter-kind, .filter-account, .filter-cat, .filter-component, .filter-routing')
      .forEach(el => el.addEventListener('change', render));
    document.getElementById('view-select').addEventListener('change', render);
    document.getElementById('sort-select').addEventListener('change', render);

    render();
  </script>
</body>
</html>
"""


def main() -> None:
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT

    if not input_path.exists():
        print(f"no input at {input_path}, run vuln_lookup.py first", file=sys.stderr)
        sys.exit(1)

    records = json.loads(input_path.read_text())
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text(build_html(records, input_path))
    print(f"wrote {output_path}")


if __name__ == "__main__":
    main()
