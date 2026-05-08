"""Export (logsource, channel) events per log source group, one Markdown file per group.

Log source group = prefix before ":" in the logsource name.
  e.g. "WinEventLog:Security" → group "WinEventLog"
       "auditd:SYSCALL"       → group "auditd"
       "Network Traffic"      → group "Network Traffic"  (no colon → self)

Events are collected from:
  x-mitre-data-component → x_mitre_log_sources [{name, channel}]

Each file contains a table of all unique (logsource, channel) pairs for that group,
alongside the Data Components that reference each event.

Usage:
  python list_logsource_events.py
  python list_logsource_events.py --outdir logsource-groups
  python list_logsource_events.py --group WinEventLog
"""

import argparse
import re
from collections import defaultdict
from pathlib import Path

from mitreattack.stix20 import MitreAttackData


def logsource_group(logsource: str) -> str:
    return logsource.split(":")[0] if ":" in logsource else logsource


def slugify(text: str) -> str:
    text = re.sub(r"\s+", "-", text.strip())
    text = re.sub(r"[^A-Za-z0-9._-]", "", text)
    return text or "untitled"


def collect_events(data: MitreAttackData) -> dict[str, list[dict]]:
    """Return {group: [{logsource, channel, dc_names}]} collected from DataComponents.

    Events with the same (logsource, channel) are merged; dc_names lists every
    DataComponent that references that event.
    """
    # (logsource, channel) → set of dc_names
    event_dcs: dict[tuple[str, str], set[str]] = defaultdict(set)

    for dc in data.get_datacomponents(remove_revoked_deprecated=True):
        dc_name = getattr(dc, "name", "") or ""
        log_sources = getattr(dc, "x_mitre_log_sources", []) or []
        for ls_entry in log_sources:
            ls = ls_entry.get("name", "").strip()
            ch = ls_entry.get("channel", "").strip()
            if not ls:
                continue
            event_dcs[(ls, ch)].add(dc_name)

    # Group by log source group prefix
    groups: dict[str, list[dict]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for (ls, ch), dc_names in sorted(event_dcs.items()):
        key = (ls, ch)
        if key in seen:
            continue
        seen.add(key)
        group = logsource_group(ls)
        groups[group].append(
            {
                "logsource": ls,
                "channel": ch,
                "dc_names": ", ".join(sorted(dc_names)),
            }
        )

    # Sort events within each group
    for group in groups:
        groups[group].sort(key=lambda r: (r["logsource"], r["channel"]))

    return dict(sorted(groups.items()))


def render_group_md(group: str, events: list[dict]) -> str:
    lines: list[str] = []
    lines.append(f"# {group}")
    lines.append("")
    lines.append(f"{len(events)} unique events")
    lines.append("")
    lines.append("| Log Source | Channel | Data Components |")
    lines.append("|------------|---------|-----------------|")
    for e in events:
        ch = e["channel"].replace("|", "\\|")
        lines.append(f"| `{e['logsource']}` | {ch} | {e['dc_names']} |")
    lines.append("")
    return "\n".join(lines)


def main():
    repo_root = Path(__file__).resolve().parents[1]
    default_stix = str(repo_root / "enterprise-attack-v18-1.json")

    parser = argparse.ArgumentParser(
        description="Export (logsource, channel) events per group to one Markdown file each."
    )
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle")
    parser.add_argument(
        "--outdir",
        default="logsource-groups",
        help="Output directory for Markdown files (default: logsource-groups/)",
    )
    parser.add_argument(
        "--group",
        default=None,
        help="Only export groups whose name contains this string (case-insensitive)",
    )
    args = parser.parse_args()

    data = MitreAttackData(args.stix)
    groups = collect_events(data)

    if args.group:
        needle = args.group.lower()
        groups = {g: evts for g, evts in groups.items() if needle in g.lower()}

    if not groups:
        print("No groups matched the filter.")
        return

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    written = []
    for group, events in groups.items():
        content = render_group_md(group, events)
        filename = slugify(group) + ".md"
        (outdir / filename).write_text(content, encoding="utf-8")
        written.append((filename, len(events)))

    total_events = sum(n for _, n in written)
    print(f"Wrote {len(written)} group files ({total_events} unique events) to {outdir.resolve()}")
    for filename, count in written:
        print(f"  {filename}  ({count} events)")


if __name__ == "__main__":
    main()
