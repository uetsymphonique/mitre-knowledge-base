import argparse
import re
from pathlib import Path

from mitreattack.stix20 import MitreAttackData


def slugify(text: str) -> str:
    if not text:
        return "untitled"
    text = re.sub(r"\s+", "-", text.strip())
    text = re.sub(r"[^A-Za-z0-9._-]", "", text)
    return text or "untitled"


def get_enterprise_tactics_in_order(data: MitreAttackData, domain: str):
    tactics_by_matrix = data.get_tactics_by_matrix()
    for matrix_name, tactics in tactics_by_matrix.items():
        if domain.split("-")[0] in matrix_name.lower():
            return tactics
    return data.get_tactics(remove_revoked_deprecated=True)


def select_tactics(data: MitreAttackData, domain: str, mode: str, tactic_names: list[str]):
    all_tactics = get_enterprise_tactics_in_order(data, domain)
    if mode == "all":
        return all_tactics

    wanted = {n.strip().lower() for n in tactic_names if n and n.strip()}
    if not wanted:
        return []

    selected = []
    for t in all_tactics:
        name = MitreAttackData.get_field(t, "name") or ""
        shortname = MitreAttackData.get_field(t, "x_mitre_shortname") or ""
        if name.lower() in wanted or shortname.lower() in wanted:
            selected.append(t)
    return selected


def write_tactic_markdown(
    data: MitreAttackData,
    domain: str,
    tactic,
    outdir: Path,
    include_detection: bool,
    include_procedures: bool,
    procedures_top: int | None,
):
    tactic_name = MitreAttackData.get_field(tactic, "name")
    shortname = MitreAttackData.get_field(tactic, "x_mitre_shortname")
    stix_id = MitreAttackData.get_field(tactic, "id")
    tactic_attack_id = data.get_attack_id(stix_id) or ""

    techniques = data.get_techniques_by_tactic(shortname, domain, remove_revoked_deprecated=True)
    technique_ids = {MitreAttackData.get_field(t, "id") for t in techniques}

    parent_techniques = [
        t for t in techniques if not MitreAttackData.get_field(t, "x_mitre_is_subtechnique", False)
    ]

    def get_tid(t):
        return data.get_attack_id(MitreAttackData.get_field(t, "id")) or ""

    parent_techniques.sort(key=lambda t: (get_tid(t), MitreAttackData.get_field(t, "name") or ""))

    lines = []

    for parent in parent_techniques:
        p_name = MitreAttackData.get_field(parent, "name")
        p_id = MitreAttackData.get_field(parent, "id")
        p_tid = data.get_attack_id(p_id) or ""
        if p_tid:
            lines.append(f"### {p_tid} - {p_name}")
        else:
            lines.append(f"### {p_name}")
        lines.append("")
        # Parent technique description, detection, and procedures (conditional)
        p_desc = (MitreAttackData.get_field(parent, "description") or "").strip()
        if p_desc:
            lines.append("Description:")
            lines.append("")
            lines.append(p_desc)
            lines.append("")
        if include_detection:
            p_det = (MitreAttackData.get_field(parent, "x_mitre_detection") or "").strip()
            if p_det:
                lines.append("Detection:")
                lines.append("")
                lines.append(p_det)
                lines.append("")
        if include_procedures:
            parent_procs = data.get_procedure_examples_by_technique(p_id)
            if procedures_top is not None and procedures_top > 0:
                parent_procs = parent_procs[:procedures_top]
            if parent_procs:
                lines.append("Procedures:")
                lines.append("")
                for r in parent_procs:
                    src_obj = data.get_object_by_stix_id(r.source_ref)
                    src_id = data.get_attack_id(src_obj.id) or ""
                    src_name = MitreAttackData.get_field(src_obj, "name") or ""
                    desc = (getattr(r, "description", "") or "").strip()
                    if src_id:
                        lines.append(f"- [{src_id}] {src_name}: {desc}")
                    else:
                        lines.append(f"- {src_name}: {desc}")
                lines.append("")

        sub_entries = data.get_subtechniques_of_technique(p_id)
        sub_techniques = [e["object"] for e in sub_entries if e.get("object") and e["object"]["id"] in technique_ids]
        sub_techniques.sort(key=lambda s: (data.get_attack_id(MitreAttackData.get_field(s, "id")) or "", MitreAttackData.get_field(s, "name") or ""))

        for s in sub_techniques:
            s_name = MitreAttackData.get_field(s, "name")
            s_id = MitreAttackData.get_field(s, "id")
            s_tid = data.get_attack_id(s_id) or ""
            full_sub_name = f"{p_name}: {s_name}" if s_name else p_name
            if s_tid:
                lines.append(f"#### {s_tid} - {full_sub_name}")
            else:
                lines.append(f"#### {full_sub_name}")
            lines.append("")
            s_desc = (MitreAttackData.get_field(s, "description") or "").strip()
            if s_desc:
                lines.append("Description:")
                lines.append("")
                lines.append(s_desc)
                lines.append("")
            if include_detection:
                s_det = (MitreAttackData.get_field(s, "x_mitre_detection") or "").strip()
                if s_det:
                    lines.append("Detection:")
                    lines.append("")
                    lines.append(s_det)
                    lines.append("")
            if include_procedures:
                sub_procs = data.get_procedure_examples_by_technique(s_id)
                if procedures_top is not None and procedures_top > 0:
                    sub_procs = sub_procs[:procedures_top]
                if sub_procs:
                    lines.append("Procedures:")
                    lines.append("")
                    for r in sub_procs:
                        src_obj = data.get_object_by_stix_id(r.source_ref)
                        src_id = data.get_attack_id(src_obj.id) or ""
                        src_name = MitreAttackData.get_field(src_obj, "name") or ""
                        desc = (getattr(r, "description", "") or "").strip()
                        if src_id:
                            lines.append(f"- [{src_id}] {src_name}: {desc}")
                        else:
                            lines.append(f"- {src_name}: {desc}")
                    lines.append("")
        lines.append("")

    # Filename: prefer ATT&CK ID + shortname
    base = "-".join(filter(None, [tactic_attack_id, shortname or tactic_name]))
    filename = slugify(base) + ".md"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / filename).write_text("\n".join(lines), encoding="utf-8")
    return filename


def parse_tactics_arg(values: list[str]) -> list[str]:
    if not values:
        return []
    result = []
    for v in values:
        if "," in v:
            result.extend([x.strip() for x in v.split(",") if x.strip()])
        else:
            result.append(v.strip())
    return result


def main():
    repo_root = Path(__file__).resolve().parents[1]
    default_stix = str(repo_root / "enterprise-attack.json")

    parser = argparse.ArgumentParser(description="Export techniques per tactic to Markdown files")
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle (enterprise-attack.json)")
    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        help="ATT&CK domain",
    )
    parser.add_argument("--mode", choices=["all", "tactic"], required=True, help="Select all tactics or a provided list")
    parser.add_argument("--tactics", nargs="*", default=[], help="Tactic names or shortnames (for mode=tactic). Accepts multiple or comma-separated.")
    parser.add_argument("--outdir", default="tactics", help="Output directory for Markdown files")
    parser.add_argument("--detection", action="store_true", help="Include Detection sections")
    parser.add_argument("--procedures", action="store_true", help="Include Procedures sections")
    parser.add_argument(
        "--procedures-top",
        type=int,
        default=None,
        help="Limit number of procedure examples per (sub)technique",
    )
    args = parser.parse_args()

    data = MitreAttackData(args.stix)
    selected = select_tactics(data, args.domain, args.mode, parse_tactics_arg(args.tactics))

    outdir = Path(args.outdir)
    written = []
    top_n = args.procedures_top if args.procedures_top and args.procedures_top > 0 else None

    for tactic in selected:
        fname = write_tactic_markdown(
            data,
            args.domain,
            tactic,
            outdir,
            include_detection=args.detection,
            include_procedures=args.procedures,
            procedures_top=top_n,
        )
        written.append(fname)

    print(f"Wrote {len(written)} files to {outdir.resolve()}")
    for f in written:
        print(f" - {f}")


if __name__ == "__main__":
    main()


