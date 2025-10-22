import argparse
import csv
from pathlib import Path

from openpyxl import load_workbook


EXPECTED_COLUMNS = ["Summary", "Technique", "Procedures", "Description"]


def normalize_text(value: object, joiner: str) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""

    # Split on any newline variant and strip each part
    parts = [seg.strip() for seg in text.replace("\r", "\n").split("\n")]
    parts = [p for p in parts if p]
    if not parts:
        return ""
    # Join with requested delimiter and collapse any leftover whitespace
    normalized = f" {joiner} ".join(parts)
    return normalized.strip()


def find_header_indices(header_cells: list[str]) -> dict[str, int]:
    indices: dict[str, int] = {}
    normalized = {str(name).strip().lower(): idx for idx, name in enumerate(header_cells)}
    for col in EXPECTED_COLUMNS:
        key = col.lower()
        if key not in normalized:
            raise ValueError(f"Required column '{col}' not found in header: {header_cells}")
        indices[col] = normalized[key]
    return indices


def main():
    parser = argparse.ArgumentParser(
        description="Normalize KB TTPs XLSX (Summary, Technique, Procedures, Description) to CSV"
    )
    parser.add_argument("input", help="Path to input .xlsx file")
    parser.add_argument(
        "--sheet",
        default=None,
        help="Worksheet name (default: first sheet)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Path to output file (default: alongside input with extension per --format)",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json", "md"],
        default="csv",
        help="Output format: csv, json, or md (default: csv)",
    )
    parser.add_argument(
        "--tech2tac",
        default=None,
        help="Optional path to tech2tac JSON to append Tactics column based on Technique IDs",
    )
    parser.add_argument(
        "--seperate-by-technique",
        action="store_true",
        help="Write one file per technique named <technique>_<timestamp> in --outdir",
    )
    parser.add_argument(
        "--outdir",
        default=None,
        help="Output directory when using --seperate-by-technique (default: alongside input)",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    # Choose default extension based on format
    default_ext = ".json" if args.format == "json" else (".md" if args.format == "md" else ".csv")
    out_path = Path(args.output) if args.output else in_path.with_suffix(default_ext)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    wb = load_workbook(filename=str(in_path), read_only=True, data_only=True)
    ws = wb[args.sheet] if args.sheet else wb.worksheets[0]

    rows_iter = ws.iter_rows(values_only=True)
    try:
        header = next(rows_iter)
    except StopIteration:
        wb.close()
        raise ValueError("Input sheet is empty")

    header_cells = [str(h) if h is not None else "" for h in header]
    col_idx = find_header_indices(header_cells)

    # Optional mapping of technique ID => [tactic IDs]
    id_to_tactics: dict[str, list[str]] | None = None
    if args.tech2tac:
        import json as _json
        map_path = Path(args.tech2tac)
        if not map_path.exists():
            raise FileNotFoundError(f"tech2tac mapping not found: {map_path}")
        id_to_tactics = _json.loads(map_path.read_text(encoding="utf-8"))

    # Collect normalized rows first (used across formats)
    records = []
    for row in rows_iter:
        cells = list(row)
        def get(col: str):
            idx = col_idx[col]
            return cells[idx] if idx < len(cells) else None

        summary = normalize_text(get("Summary"), ".")
        technique = normalize_text(get("Technique"), ".")
        procedures = normalize_text(get("Procedures"), ";")
        description = normalize_text(get("Description"), ".")

        # Build Behavior (for csv/json): concatenate non-empty segments with labels
        segments = []
        if summary:
            segments.append(f"Summary: {summary}.")
        if description:
            segments.append(f"Description: {description}.")
        if procedures:
            segments.append(f"Procedures: {procedures}.")
        behavior = " ".join(segments).strip()

        record = {
            "Technique": technique,
            "Behavior": behavior,
            # Keep normalized fields for MD rendering
            "_Summary": summary,
            "_Description": description,
            "_Procedures": procedures,
        }

        # Append Tactics via mapping if provided
        if id_to_tactics is not None:
            import re as _re
            # Extract all technique IDs from the Technique field
            tech_ids = _re.findall(r"T\d{4}(?:\.\d{3})?", technique)
            tactics_set: set[str] = set()
            for tid in tech_ids:
                if tid in id_to_tactics and id_to_tactics[tid]:
                    for tac in id_to_tactics[tid]:
                        tactics_set.add(str(tac))
            tactics_list = sorted(tactics_set)
            record["Tactics"] = "; ".join(tactics_list) if args.format == "csv" else tactics_list

        records.append(record)

    # Separate into per-technique files if requested
    if args.seperate_by_technique:
        from datetime import datetime

        def sanitize_filename(name: str) -> str:
            safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)
            return safe.strip("._") or "unknown"

        groups: dict[str, list[dict]] = {}
        for rec in records:
            tech_key = rec.get("Technique", "").strip() or "unknown"
            groups.setdefault(tech_key, []).append(rec)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_outdir = Path(args.outdir) if args.outdir else in_path.parent
        base_outdir.mkdir(parents=True, exist_ok=True)

        written_files = 0
        for tech, recs in groups.items():
            ext = 'json' if args.format == 'json' else ('md' if args.format == 'md' else 'csv')
            fname = f"{sanitize_filename(tech)}_{ts}.{ext}"
            fpath = base_outdir / fname
            if args.format == "json":
                import json
                fpath.write_text(json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")
            elif args.format == "md":
                # Header: ### Technique (tactics)
                lines = []
                tac_set = set()
                for r in recs:
                    tval = r.get("Tactics")
                    if isinstance(tval, list):
                        tac_set.update(tval)
                    elif isinstance(tval, str) and tval:
                        tac_set.update([x.strip() for x in tval.split(";") if x.strip()])
                tac_str = f" ({', '.join(sorted(tac_set))})" if tac_set else ""
                lines.append(f"### {tech}{tac_str}")
                # Body: three paragraphs (_Summary, _Description, _Procedures) separated by blank lines
                paras = []
                # Use first record's non-empty entries per paragraph
                s = next((r.get("_Summary") for r in recs if r.get("_Summary")), "")
                d = next((r.get("_Description") for r in recs if r.get("_Description")), "")
                p = next((r.get("_Procedures") for r in recs if r.get("_Procedures")), "")
                for part in [s, d, p]:
                    if part:
                        paras.append(part)
                if paras:
                    lines.append("\n\n".join(paras))
                fpath.write_text("\n".join(lines) + "\n", encoding="utf-8")
            else:
                with fpath.open("w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    headers = ["Technique", "Behavior"] + (["Tactics"] if id_to_tactics is not None else [])
                    writer.writerow(headers)
                    for r in recs:
                        row_vals = [r["Technique"], r["Behavior"]]
                        if id_to_tactics is not None:
                            row_vals.append(r.get("Tactics", ""))
                        writer.writerow(row_vals)
            written_files += 1
        print(f"Saved {written_files} files to {base_outdir}")
    else:
        if args.format == "json":
            import json
            out_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        elif args.format == "md":
            lines = []
            for r in records:
                tech = r.get("Technique", "")
                tval = r.get("Tactics")
                tac_list = []
                if isinstance(tval, list):
                    tac_list = tval
                elif isinstance(tval, str) and tval:
                    tac_list = [x.strip() for x in tval.split(";") if x.strip()]
                tac_str = f" ({', '.join(sorted(tac_list))})" if tac_list else ""
                lines.append(f"### {tech}{tac_str}\n")
                # Body: three paragraphs from _Summary, _Description, _Procedures
                parts = [r.get("_Summary") or "", r.get("_Description") or "", r.get("_Procedures") or ""]
                paras = [p for p in parts if p]
                if paras:
                    lines.append("\n\n".join(paras))
                lines.append("")
            out_path.write_text("\n".join(lines), encoding="utf-8")
        else:
            with out_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                # Output columns: Technique, Behavior (+ optional Tactics)
                headers = ["Technique", "Behavior"] + (["Tactics"] if id_to_tactics is not None else [])
                writer.writerow(headers)
                for rec in records:
                    row_vals = [rec["Technique"], rec["Behavior"]]
                    if id_to_tactics is not None:
                        row_vals.append(rec.get("Tactics", ""))
                    writer.writerow(row_vals)

    wb.close()
    if not args.seperate_by_technique:
        print(f"Saved normalized {args.format.upper()} to {out_path}")


if __name__ == "__main__":
    main()


