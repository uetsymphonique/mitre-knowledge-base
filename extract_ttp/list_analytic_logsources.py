"""Extract all MITRE ATT&CK analytics with their log source references.

Output columns per row (one row per log source reference per analytic):
  an_id        - ATT&CK Analytic ID  (AN-xxxx)
  platforms    - comma-separated platform list
  logsource    - ref["name"]  e.g. "WinEventLog:Security"
  channel      - ref["channel"]
  dc_id        - ATT&CK DataComponent ID (DC-xxxx)
  dc_name      - DataComponent name  e.g. "Process Creation"

Usage examples:
  python list_analytic_logsources.py
  python list_analytic_logsources.py --format markdown
  python list_analytic_logsources.py --format csv --out logsources.csv
  python list_analytic_logsources.py --logsource "WinEventLog:Security"
  python list_analytic_logsources.py --platform Windows
  python list_analytic_logsources.py --exclude-platform Windows macOS

  # Unique log source list + group breakdown printed to console
  python list_analytic_logsources.py --logsource-stats
  python list_analytic_logsources.py --logsource-stats --format csv --out ls_groups.csv
"""

import argparse
import csv
import io
import sys
from pathlib import Path

from mitreattack.stix20 import MitreAttackData


def build_rows(data: MitreAttackData) -> list[dict]:
    """Return one dict per (analytic × log_source_reference) pair."""
    # Pre-build DC stix_id → (attack_id, name) lookup to avoid repeated queries
    dc_lookup: dict[str, tuple[str, str]] = {}
    for dc in data.get_datacomponents(remove_revoked_deprecated=False):
        stix_id = dc.id
        attack_id = data.get_attack_id(stix_id) or ""
        name = getattr(dc, "name", "") or ""
        dc_lookup[stix_id] = (attack_id, name)

    rows = []
    analytics = data.get_analytics(remove_revoked_deprecated=True)
    for an in analytics:
        an_id = data.get_attack_id(an.id) or ""
        platforms = getattr(an, "x_mitre_platforms", []) or []
        platforms_str = ", ".join(platforms)

        log_refs = getattr(an, "x_mitre_log_source_references", []) or []

        if not log_refs:
            # Analytic has no log sources — still emit one row with blanks
            rows.append(
                {
                    "an_id": an_id,
                    "platforms": platforms_str,
                    "logsource": "",
                    "channel": "",
                    "dc_id": "",
                    "dc_name": "",
                }
            )
            continue

        for ref in log_refs:
            ls_name = ref.get("name", "")
            ls_channel = ref.get("channel", "")
            dc_ref = ref.get("x_mitre_data_component_ref", "")
            dc_attack_id, dc_name = dc_lookup.get(dc_ref, ("", ""))
            rows.append(
                {
                    "an_id": an_id,
                    "platforms": platforms_str,
                    "logsource": ls_name,
                    "channel": ls_channel,
                    "dc_id": dc_attack_id,
                    "dc_name": dc_name,
                }
            )

    rows.sort(key=lambda r: (r["an_id"], r["logsource"]))
    return rows


def filter_rows(
    rows: list[dict],
    logsource: str | None,
    platform: str | None,
    exclude_platforms: list[str] | None,
) -> list[dict]:
    if logsource:
        ls_lower = logsource.lower()
        rows = [r for r in rows if ls_lower in r["logsource"].lower()]
    if platform:
        pl_lower = platform.lower()
        rows = [r for r in rows if pl_lower in r["platforms"].lower()]
    if exclude_platforms:
        excl = [p.lower() for p in exclude_platforms]
        rows = [r for r in rows if not any(e in r["platforms"].lower() for e in excl)]
    return rows


COLUMNS = ["an_id", "platforms", "logsource", "channel", "dc_id", "dc_name"]
HEADERS = {
    "an_id": "Analytic ID",
    "platforms": "Platforms",
    "logsource": "Log Source",
    "channel": "Channel",
    "dc_id": "DC ID",
    "dc_name": "Data Component",
}


def render_markdown(rows: list[dict]) -> str:
    widths = {c: len(HEADERS[c]) for c in COLUMNS}
    for r in rows:
        for c in COLUMNS:
            widths[c] = max(widths[c], len(r[c]))

    def fmt_row(vals: dict[str, str]) -> str:
        return "| " + " | ".join(vals[c].ljust(widths[c]) for c in COLUMNS) + " |"

    sep = "|-" + "-|-".join("-" * widths[c] for c in COLUMNS) + "-|"
    lines = [fmt_row(HEADERS), sep] + [fmt_row(r) for r in rows]
    return "\n".join(lines)


def render_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS)
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def render_table(rows: list[dict]) -> str:
    """Simple aligned plain-text table."""
    widths = {c: len(HEADERS[c]) for c in COLUMNS}
    for r in rows:
        for c in COLUMNS:
            widths[c] = max(widths[c], len(r[c]))

    def fmt(vals: dict[str, str]) -> str:
        return "  ".join(vals[c].ljust(widths[c]) for c in COLUMNS)

    sep = "  ".join("-" * widths[c] for c in COLUMNS)
    lines = [fmt(HEADERS), sep] + [fmt(r) for r in rows]
    return "\n".join(lines)


def build_logsource_group_stats(rows: list[dict]) -> tuple[list[str], list[dict]]:
    """Return (sorted unique logsources, group summary rows).

    A logsource like "WinEventLog:Security" belongs to group "WinEventLog".
    A logsource without ":" is its own group.
    Group summary rows: [{group, count, platforms, dc_names, members}] sorted by group name.
    Platforms and dc_names = union across all rows that reference any logsource in the group.
    """
    from collections import defaultdict

    unique_ls: set[str] = {r["logsource"] for r in rows if r["logsource"]}
    sorted_ls = sorted(unique_ls)

    groups: dict[str, list[str]] = defaultdict(list)
    for ls in sorted_ls:
        group = ls.split(":")[0] if ":" in ls else ls
        groups[group].append(ls)

    group_platforms: dict[str, set[str]] = defaultdict(set)
    group_dcs: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        if not r["logsource"]:
            continue
        group = r["logsource"].split(":")[0] if ":" in r["logsource"] else r["logsource"]
        for p in (p.strip() for p in r["platforms"].split(",") if p.strip()):
            group_platforms[group].add(p)
        if r["dc_name"]:
            group_dcs[group].add(r["dc_name"])

    group_rows = [
        {
            "group": g,
            "count": str(len(members)),
            "platforms": ", ".join(sorted(group_platforms.get(g, set()))),
            "dc_names": ", ".join(sorted(group_dcs.get(g, set()))),
            "members": ", ".join(members),
        }
        for g, members in sorted(groups.items())
    ]
    return sorted_ls, group_rows


def print_logsource_group_report(sorted_ls: list[str], group_rows: list[dict]) -> None:
    """Print a human-readable breakdown to stdout."""
    total_unique = len(sorted_ls)
    total_groups = len(group_rows)
    max_group_len = max((len(r["group"]) for r in group_rows), default=5)
    max_plat_len = min(max((len(r["platforms"]) for r in group_rows), default=9), 35)
    max_dc_len = min(max((len(r["dc_names"]) for r in group_rows), default=14), 55)

    print(f"=== Log Source Groups ({total_groups} groups, {total_unique} unique log sources) ===\n")
    header = (
        f"{'Group':<{max_group_len}}  {'Count':>5}  "
        f"{'Platforms':<{max_plat_len}}  {'Data Components':<{max_dc_len}}  Members"
    )
    sep = (
        "-" * max_group_len + "  " + "-" * 5 + "  "
        + "-" * max_plat_len + "  " + "-" * max_dc_len + "  " + "-" * 40
    )
    print(header)
    print(sep)
    for r in group_rows:
        plat_display = r["platforms"]
        if len(plat_display) > max_plat_len:
            plat_display = plat_display[: max_plat_len - 3] + "..."
        dc_display = r["dc_names"]
        if len(dc_display) > max_dc_len:
            dc_display = dc_display[: max_dc_len - 3] + "..."
        members_preview = r["members"]
        if len(members_preview) > 60:
            members_preview = members_preview[:57] + "..."
        print(
            f"{r['group']:<{max_group_len}}  {r['count']:>5}  "
            f"{plat_display:<{max_plat_len}}  {dc_display:<{max_dc_len}}  {members_preview}"
        )
    print()
    print(f"Total: {total_unique} unique log sources across {total_groups} groups")


def main():
    repo_root = Path(__file__).resolve().parents[1]
    default_stix = str(repo_root / "enterprise-attack-v18-1.json")

    parser = argparse.ArgumentParser(
        description="List all MITRE ATT&CK analytics with their log source references."
    )
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle")
    parser.add_argument(
        "--format",
        choices=["table", "markdown", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--out", default=None, help="Write output to file (default: stdout)")
    parser.add_argument(
        "--logsource",
        default=None,
        help="Filter rows: keep only rows where Log Source contains this string (case-insensitive)",
    )
    parser.add_argument(
        "--platform",
        default=None,
        help="Filter rows: keep only rows where Platforms contains this string (case-insensitive)",
    )
    parser.add_argument(
        "--exclude-platform",
        dest="exclude_platforms",
        nargs="+",
        default=[],
        metavar="PLATFORM",
        help="Exclude rows where Platforms contains any of these strings (case-insensitive, space-separated)",
    )
    parser.add_argument(
        "--no-empty",
        action="store_true",
        help="Exclude analytics that have no log source references",
    )
    parser.add_argument(
        "--logsource-stats",
        action="store_true",
        help=(
            "Print unique log sources and group breakdown (group = prefix before ':') to console. "
            "If --out is given, also write the group summary table to that file."
        ),
    )
    args = parser.parse_args()

    data = MitreAttackData(args.stix)
    rows = build_rows(data)

    if args.no_empty:
        rows = [r for r in rows if r["logsource"]]

    rows = filter_rows(rows, args.logsource, args.platform, args.exclude_platforms or [])

    if not rows:
        print("No rows matched the filter criteria.", file=sys.stderr)
        sys.exit(0)

    total = len(rows)
    unique_logsources = len({r["logsource"] for r in rows if r["logsource"]})
    unique_analytics = len({r["an_id"] for r in rows if r["an_id"]})

    # --- Log source group breakdown mode ---
    if args.logsource_stats:
        sorted_ls, group_rows = build_logsource_group_stats(rows)
        print_logsource_group_report(sorted_ls, group_rows)

        if args.out:
            ls_cols = ["group", "count", "platforms", "dc_names", "members"]
            ls_headers = {
                "group": "Group",
                "count": "Count",
                "platforms": "Platforms",
                "dc_names": "Data Components",
                "members": "Members",
            }
            if args.format == "csv":
                buf = io.StringIO()
                w = csv.DictWriter(buf, fieldnames=ls_cols)
                w.writeheader()
                w.writerows(group_rows)
                Path(args.out).write_text(buf.getvalue(), encoding="utf-8")
            elif args.format == "markdown":
                widths = {c: len(ls_headers[c]) for c in ls_cols}
                for r in group_rows:
                    for c in ls_cols:
                        widths[c] = max(widths[c], len(r[c]))
                def _fmt_md(vals):
                    return "| " + " | ".join(vals[c].ljust(widths[c]) for c in ls_cols) + " |"
                sep_md = "|-" + "-|-".join("-" * widths[c] for c in ls_cols) + "-|"
                md_lines = [_fmt_md(ls_headers), sep_md] + [_fmt_md(r) for r in group_rows]
                Path(args.out).write_text("\n".join(md_lines), encoding="utf-8")
            else:
                widths = {c: len(ls_headers[c]) for c in ls_cols}
                for r in group_rows:
                    for c in ls_cols:
                        widths[c] = max(widths[c], len(r[c]))
                def _fmt_txt(vals):
                    return "  ".join(vals[c].ljust(widths[c]) for c in ls_cols)
                sep_txt = "  ".join("-" * widths[c] for c in ls_cols)
                txt_lines = [_fmt_txt(ls_headers), sep_txt] + [_fmt_txt(r) for r in group_rows]
                Path(args.out).write_text("\n".join(txt_lines), encoding="utf-8")
            print(f"\nGroup summary written to {args.out}")
        return

    # --- Full analytic table ---
    if args.format == "markdown":
        output = render_markdown(rows)
    elif args.format == "csv":
        output = render_csv(rows)
    else:
        output = render_table(rows)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Wrote {total} rows ({unique_analytics} analytics, {unique_logsources} unique log sources) to {args.out}")
    else:
        print(output)
        print(f"\n({total} rows | {unique_analytics} analytics | {unique_logsources} unique log sources)")


if __name__ == "__main__":
    main()
