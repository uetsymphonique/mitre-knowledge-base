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
        choices=["csv", "json"],
        default="csv",
        help="Output format (default: csv)",
    )
    parser.add_argument(
        "--tech2tac",
        default=None,
        help="Optional path to tech2tac JSON to append Tactics column based on Technique IDs",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    # Choose default extension based on format
    default_ext = ".json" if args.format == "json" else ".csv"
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

    # Collect normalized rows first (useful for both formats)
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

        # Build Behavior: concatenate non-empty segments with labels
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

    if args.format == "json":
        import json
        out_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
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
    print(f"Saved normalized {args.format.upper()} to {out_path}")


if __name__ == "__main__":
    main()


