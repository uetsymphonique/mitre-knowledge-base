"""Export each MITRE ATT&CK DataComponent as a separate Markdown file.

Each file contains:
  - DC ID + name as heading
  - Parent DataSource
  - Description
  - Log Sources (x_mitre_log_sources)
  - Techniques detected by this DataComponent (ID, name, tactics)

Usage:
  python export_datacomponents.py
  python export_datacomponents.py --outdir datacomponents
  python export_datacomponents.py --domain enterprise-attack
  python export_datacomponents.py --filter "Process Creation"
  python export_datacomponents.py --no-techniques
"""

import argparse
import re
from pathlib import Path

from mitreattack.stix20 import MitreAttackData


def slugify(text: str) -> str:
    text = re.sub(r"\s+", "-", text.strip())
    text = re.sub(r"[^A-Za-z0-9._-]", "", text)
    return text or "untitled"


def get_datasource_name(data: MitreAttackData, ds_ref: str) -> str:
    if not ds_ref:
        return ""
    try:
        ds_obj = data.get_object_by_stix_id(ds_ref)
        return MitreAttackData.get_field(ds_obj, "name") or ""
    except Exception:
        return ""


def get_tactic_names(data: MitreAttackData, technique) -> list[str]:
    tactics = data.get_tactics_by_technique(MitreAttackData.get_field(technique, "id"))
    return sorted(MitreAttackData.get_field(t, "name") or "" for t in tactics)


def render_datacomponent_md(
    data: MitreAttackData,
    dc,
    include_techniques: bool,
) -> str:
    dc_stix_id = MitreAttackData.get_field(dc, "id")
    dc_attack_id = data.get_attack_id(dc_stix_id) or ""
    dc_name = MitreAttackData.get_field(dc, "name") or ""
    description = (MitreAttackData.get_field(dc, "description") or "").strip()
    ds_ref = MitreAttackData.get_field(dc, "x_mitre_data_source_ref") or ""
    ds_name = get_datasource_name(data, ds_ref)
    log_sources = MitreAttackData.get_field(dc, "x_mitre_log_sources") or []

    lines: list[str] = []

    # --- Heading ---
    heading = f"{dc_attack_id} - {dc_name}" if dc_attack_id else dc_name
    lines.append(f"# {heading}")
    lines.append("")

    # --- Metadata ---
    if ds_name:
        lines.append(f"**Data Source:** {ds_name}")
        lines.append("")

    # --- Description ---
    if description:
        lines.append("## Description")
        lines.append("")
        lines.append(description)
        lines.append("")

    # --- Log Sources ---
    if log_sources:
        lines.append("## Log Sources")
        lines.append("")
        lines.append("| Log Source | Channel |")
        lines.append("|------------|---------|")
        for ls in log_sources:
            name = ls.get("name", "")
            channel = ls.get("channel", "").replace("|", "\\|")
            lines.append(f"| `{name}` | {channel} |")
        lines.append("")

    # --- Techniques ---
    if include_techniques:
        tech_entries = data.get_techniques_detected_by_datacomponent(dc_stix_id)
        if tech_entries:
            lines.append("## Techniques Detected")
            lines.append("")
            lines.append("| Technique ID | Name | Tactics |")
            lines.append("|-------------|------|---------|")
            rows = []
            for entry in tech_entries:
                tech = entry["object"]
                t_stix_id = MitreAttackData.get_field(tech, "id")
                t_id = data.get_attack_id(t_stix_id) or ""
                t_name = MitreAttackData.get_field(tech, "name") or ""
                tactic_names = get_tactic_names(data, tech)
                tactics_str = ", ".join(tactic_names)
                rows.append((t_id, t_name, tactics_str))

            rows.sort(key=lambda r: r[0])
            for t_id, t_name, tactics_str in rows:
                lines.append(f"| {t_id} | {t_name} | {tactics_str} |")
            lines.append("")

    return "\n".join(lines)


def main():
    repo_root = Path(__file__).resolve().parents[1]
    default_stix = str(repo_root / "enterprise-attack-v18-1.json")

    parser = argparse.ArgumentParser(
        description="Export each MITRE ATT&CK DataComponent as a Markdown file."
    )
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle")
    parser.add_argument(
        "--outdir",
        default="datacomponents",
        help="Output directory for Markdown files (default: datacomponents/)",
    )
    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        help="ATT&CK domain filter (default: enterprise-attack)",
    )
    parser.add_argument(
        "--filter",
        dest="name_filter",
        default=None,
        help="Only export DataComponents whose name contains this string (case-insensitive)",
    )
    parser.add_argument(
        "--no-techniques",
        action="store_true",
        help="Omit the Techniques Detected section",
    )
    args = parser.parse_args()

    data = MitreAttackData(args.stix)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    datacomponents = data.get_datacomponents(remove_revoked_deprecated=True)

    # Filter by domain
    datacomponents = [
        dc for dc in datacomponents
        if args.domain in (MitreAttackData.get_field(dc, "x_mitre_domains") or [])
    ]

    # Optional name filter
    if args.name_filter:
        needle = args.name_filter.lower()
        datacomponents = [
            dc for dc in datacomponents
            if needle in (MitreAttackData.get_field(dc, "name") or "").lower()
        ]

    datacomponents.sort(
        key=lambda dc: data.get_attack_id(MitreAttackData.get_field(dc, "id")) or ""
    )

    written = []
    for dc in datacomponents:
        dc_stix_id = MitreAttackData.get_field(dc, "id")
        dc_attack_id = data.get_attack_id(dc_stix_id) or ""
        dc_name = MitreAttackData.get_field(dc, "name") or "untitled"

        content = render_datacomponent_md(data, dc, include_techniques=not args.no_techniques)

        base = "-".join(filter(None, [dc_attack_id, dc_name]))
        filename = slugify(base) + ".md"
        (outdir / filename).write_text(content, encoding="utf-8")
        written.append(filename)

    print(f"Wrote {len(written)} DataComponent files to {outdir.resolve()}")
    for f in written:
        print(f"  {f}")


if __name__ == "__main__":
    main()
