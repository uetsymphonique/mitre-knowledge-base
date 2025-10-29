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


def sanitize_text(text: str) -> str:
    if not text:
        return ""
    # Remove (Citation: ...)
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    # Remove Markdown links [text](url) -> text
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    # Remove bare URLs
    text = re.sub(r"https?://\S+", "", text)
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", "", text)
    # Collapse excessive whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


def write_tactic_txt(
    data: MitreAttackData,
    domain: str,
    tactic,
    outdir: Path,
    include_description: bool,
    include_detection: bool,
    include_procedures: bool,
    procedures_top: int | None,
    sanitize: bool,
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

    def end_block():
        # ensure exactly two blank lines at the end of a block
        while lines and lines[-1] == "":
            lines.pop()
        lines.append("")
        lines.append("")


    for parent in parent_techniques:
        p_name = MitreAttackData.get_field(parent, "name")
        p_id = MitreAttackData.get_field(parent, "id")
        p_tid = data.get_attack_id(p_id) or ""

        # Determine sub-techniques first (within this tactic)
        sub_entries = data.get_subtechniques_of_technique(p_id)
        sub_techniques = [
            e["object"] for e in sub_entries if e.get("object") and e["object"]["id"] in technique_ids
        ]
        sub_techniques.sort(
            key=lambda s: (
                data.get_attack_id(MitreAttackData.get_field(s, "id")) or "",
                MitreAttackData.get_field(s, "name") or "",
            )
        )
        
        # Always include parent technique (even if it has sub-techniques)
        if p_tid:
            lines.append(f"{p_tid} - {p_name}")
        else:
            lines.append(f"{p_name}")

        # Parent technique description, detection, and procedures (conditional)
        p_desc_raw = (MitreAttackData.get_field(parent, "description") or "").strip()
        p_desc = sanitize_text(p_desc_raw) if sanitize else p_desc_raw
        if include_description and p_desc:
            lines.append(p_desc)
        if include_detection:
            p_det_raw = (MitreAttackData.get_field(parent, "x_mitre_detection") or "").strip()
            p_det = sanitize_text(p_det_raw) if sanitize else p_det_raw
            if p_det:
                lines.append(p_det)
        if include_procedures:
            parent_procs = data.get_procedure_examples_by_technique(p_id)
            if procedures_top is not None and procedures_top > 0:
                parent_procs = parent_procs[:procedures_top]
            if parent_procs:
                proc_lines = []
                proc_acc_len = 0
                for r in parent_procs:
                    src_obj = data.get_object_by_stix_id(r.source_ref)
                    src_id = data.get_attack_id(src_obj.id) or ""
                    src_name = MitreAttackData.get_field(src_obj, "name") or ""
                    desc_raw = (getattr(r, "description", "") or "").strip()
                    desc = sanitize_text(desc_raw) if sanitize else desc_raw
                    if src_id:
                        bullet = f"[{src_id}] {src_name}: {desc}"
                    else:
                        bullet = f"{src_name}: {desc}"
                    proc_lines.append(bullet)
                    proc_acc_len += len(bullet)
                lines.append(" ".join(proc_lines))
            else:
                # Placeholder with description when no procedure examples are present
                if p_desc:
                    lines.append(p_desc)

        # end of parent block
        end_block()

        for s in sub_techniques:
            s_name = MitreAttackData.get_field(s, "name")
            s_id = MitreAttackData.get_field(s, "id")
            s_tid = data.get_attack_id(s_id) or ""
            full_sub_name = f"{p_name}: {s_name}" if s_name else p_name
            # Plain text format: just the technique name
            if s_tid:
                lines.append(f"{s_tid} - {full_sub_name}")
            else:
                lines.append(f"{full_sub_name}")
            s_desc_raw = (MitreAttackData.get_field(s, "description") or "").strip()
            s_desc = sanitize_text(s_desc_raw) if sanitize else s_desc_raw
            if include_description and s_desc:
                lines.append(s_desc)
            if include_detection:
                s_det_raw = (MitreAttackData.get_field(s, "x_mitre_detection") or "").strip()
                s_det = sanitize_text(s_det_raw) if sanitize else s_det_raw
                if s_det:
                    lines.append(s_det)
            if include_procedures:
                sub_procs = data.get_procedure_examples_by_technique(s_id)
                if procedures_top is not None and procedures_top > 0:
                    sub_procs = sub_procs[:procedures_top]
                if sub_procs:
                    proc_lines = []
                    proc_acc_len = 0
                    for r in sub_procs:
                        src_obj = data.get_object_by_stix_id(r.source_ref)
                        src_id = data.get_attack_id(src_obj.id) or ""
                        src_name = MitreAttackData.get_field(src_obj, "name") or ""
                        desc_raw = (getattr(r, "description", "") or "").strip()
                        desc = sanitize_text(desc_raw) if sanitize else desc_raw
                        if src_id:
                            bullet = f"[{src_id}] {src_name}: {desc}"
                        else:
                            bullet = f"{src_name}: {desc}"
                        proc_lines.append(bullet)
                        proc_acc_len += len(bullet)
                    lines.append(" ".join(proc_lines))
                else:
                    # Placeholder with description when no procedure examples are present
                    if s_desc:
                        lines.append(s_desc)
            # end of sub-technique block
            end_block()
    # Filename: prefer ATT&CK ID + shortname
    base = "-".join(filter(None, [tactic_attack_id, shortname or tactic_name]))
    filename = slugify(base) + ".txt"
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

    parser = argparse.ArgumentParser(description="Export techniques per tactic to TXT files")
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle (enterprise-attack.json)")
    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        help="ATT&CK domain",
    )
    parser.add_argument("--mode", choices=["all", "tactic"], required=True, help="Select all tactics or a provided list")
    parser.add_argument("--tactics", nargs="*", default=[], help="Tactic names or shortnames (for mode=tactic). Accepts multiple or comma-separated.")
    parser.add_argument("--outdir", default="tactics", help="Output directory for TXT files")
    parser.add_argument("--description", action="store_true", help="Include Description sections")
    parser.add_argument("--detection", action="store_true", help="Include Detection sections")
    parser.add_argument("--procedures", action="store_true", help="Include Procedures sections")
    parser.add_argument(
        "--procedures-top",
        type=int,
        default=None,
        help="Limit number of procedure examples per (sub)technique",
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help="Sanitize text output (remove citations, links, HTML)",
    )
    # Default behavior: include all parent techniques and sub-techniques
    parser.add_argument(
        "--single-file",
        default=None,
        help="Aggregate all selected tactics into a single TXT file (dedupe techniques, add tactics list in headers)",
    )
    args = parser.parse_args()

    data = MitreAttackData(args.stix)
    selected = select_tactics(data, args.domain, args.mode, parse_tactics_arg(args.tactics))

    outdir = Path(args.outdir)
    written = []
    top_n = args.procedures_top if args.procedures_top and args.procedures_top > 0 else None


    # Aggregate mode: write one combined TXT file
    if args.single_file:
        # tactic title formatter: "TAxxxx - Name"
        def format_tactic_title(tactic_obj) -> str:
            tid = data.get_attack_id(MitreAttackData.get_field(tactic_obj, "id") or "") or ""
            tname = MitreAttackData.get_field(tactic_obj, "name") or ""
            return (tid + (" - " + tname if tname else "")).strip()

        # aggregated by technique STIX id
        aggregated: dict[str, dict] = {}

        def add_or_merge_tech(tech, display_name: str, tactic_title: str):
            stix_id = MitreAttackData.get_field(tech, "id")
            attack_id = data.get_attack_id(stix_id) or ""
            key = stix_id
            desc_raw = (MitreAttackData.get_field(tech, "description") or "").strip()
            desc = sanitize_text(desc_raw) if args.sanitize else desc_raw
            det_raw = (MitreAttackData.get_field(tech, "x_mitre_detection") or "").strip()
            det = sanitize_text(det_raw) if args.sanitize else det_raw

            if key not in aggregated:
                aggregated[key] = {
                    "attack_id": attack_id,
                    "name": display_name,
                    "description": desc or None,
                    "detection": det or None,
                    "procedures": [],
                    "tactics": set([tactic_title] if tactic_title else []),
                }
            else:
                entry = aggregated[key]
                # prefer existing non-empty; fill if missing
                if args.description and (not entry.get("description") and desc):
                    entry["description"] = desc
                if args.detection and (not entry.get("detection") and det):
                    entry["detection"] = det
                if tactic_title:
                    entry["tactics"].add(tactic_title)

            # procedures
            if args.procedures:
                procs = data.get_procedure_examples_by_technique(stix_id)
                if top_n:
                    procs = procs[:top_n]
                acc_len = 0
                lines_local = []
                for r in procs:
                    src_obj = data.get_object_by_stix_id(r.source_ref)
                    src_id = data.get_attack_id(src_obj.id) or ""
                    src_name = MitreAttackData.get_field(src_obj, "name") or ""
                    proc_desc_raw = (getattr(r, "description", "") or "").strip()
                    proc_desc = sanitize_text(proc_desc_raw) if args.sanitize else proc_desc_raw
                    bullet = f"- [{src_id}] {src_name}: {proc_desc}" if src_id else f"- {src_name}: {proc_desc}"
                    lines_local.append(bullet)
                    acc_len += len(bullet)
                if lines_local:
                    # merge uniquely
                    existing = aggregated[key]["procedures"]
                    if not existing:
                        aggregated[key]["procedures"] = lines_local
                    else:
                        aggregated[key]["procedures"] = existing + [x for x in lines_local if x not in existing]

        # Build aggregated content by iterating selected tactics
        for tactic in selected:
            tactic_title = format_tactic_title(tactic)
            shortname = MitreAttackData.get_field(tactic, "x_mitre_shortname")
            techs = data.get_techniques_by_tactic(shortname, args.domain, remove_revoked_deprecated=True)
            tech_ids = {MitreAttackData.get_field(t, "id") for t in techs}
            parents = [t for t in techs if not MitreAttackData.get_field(t, "x_mitre_is_subtechnique", False)]
            def tid_of(t):
                return data.get_attack_id(MitreAttackData.get_field(t, "id")) or ""
            parents.sort(key=lambda t: (tid_of(t), MitreAttackData.get_field(t, "name") or ""))

            for parent in parents:
                p_name = MitreAttackData.get_field(parent, "name")
                p_id = MitreAttackData.get_field(parent, "id")
                # find subs
                sub_entries = data.get_subtechniques_of_technique(p_id)
                subs = [e["object"] for e in sub_entries if e.get("object") and e["object"]["id"] in tech_ids]
                subs.sort(key=lambda s: (data.get_attack_id(MitreAttackData.get_field(s, "id")) or "", MitreAttackData.get_field(s, "name") or ""))

                # Always include parent technique (even if it has sub-techniques)
                add_or_merge_tech(parent, p_name or "", tactic_title)

                # add subs
                for s in subs:
                    s_name = MitreAttackData.get_field(s, "name")
                    display_name = f"{p_name}: {s_name}" if s_name else (p_name or "")
                    add_or_merge_tech(s, display_name, tactic_title)

        # Now render aggregated markdown
        # sort by attack_id then name
        items = sorted(
            aggregated.values(),
            key=lambda x: (x.get("attack_id") or "", x.get("name") or ""),
        )
        out_lines: list[str] = []
        for item in items:
            attack_id = item.get("attack_id") or ""
            name = item.get("name") or ""
            tactics_list = sorted(list(item.get("tactics") or []))
            header = f"{attack_id} - {name} ({', '.join(tactics_list)})" if tactics_list else f"{attack_id} - {name}"
            out_lines.append(header)
            if args.description and item.get("description"):
                out_lines.append(item["description"])
            if args.detection and item.get("detection"):
                out_lines.append(item["detection"])
            if args.procedures and item.get("procedures"):
                out_lines.append(" ".join(item["procedures"]))
            
            # Add spacing between techniques (2 blank lines like per-tactic mode)
            out_lines.append("")
            out_lines.append("")

        # Write one file
        out_path = Path(args.single_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(out_lines), encoding="utf-8")
        written.append(str(out_path))

        print(f"Wrote single file to {out_path.resolve()}")
    else:
        # Per-tactic files (existing behavior)
        for tactic in selected:
            fname = write_tactic_txt(
                data,
                args.domain,
                tactic,
                outdir,
                include_description=args.description,
                include_detection=args.detection,
                include_procedures=args.procedures,
                procedures_top=top_n,
                sanitize=args.sanitize,
            )
            written.append(fname)

        print(f"Wrote {len(written)} files to {outdir.resolve()}")
        for f in written:
            print(f" - {f}")



if __name__ == "__main__":
    main()


