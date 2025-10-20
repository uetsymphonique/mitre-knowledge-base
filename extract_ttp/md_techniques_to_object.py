import argparse
import json
import re
from pathlib import Path


SECTION_PARENT = re.compile(r"^###\s+(?P<id>T\d{4}(?:\.\d{3})?)\s+-\s+(?P<name>.+)$")
SECTION_SUB = re.compile(r"^####\s+(?P<id>T\d{4}\.\d{3})\s+-\s+(?P<full>.+)$")


def collect_md_files(inputs: list[str]) -> list[Path]:
    md_files: list[Path] = []
    for p in inputs:
        path = Path(p)
        if path.is_dir():
            md_files.extend(sorted(path.glob("*.md")))
        elif path.is_file() and path.suffix.lower() == ".md":
            md_files.append(path)
    return md_files


def parse_markdown(path: Path) -> list[dict]:
    items = []
    with path.open("r", encoding="utf-8") as f:
        lines = [line.rstrip("\n") for line in f]

    current = None
    mode = None  # None | "desc" | "det" | "proc"

    def format_tactics(stem: str) -> str:
        # Convert filename stem like "TA0007-discovery" -> "TA0007 Discovery"
        stem = stem.replace("-", " ")
        parts = stem.split()
        if not parts:
            return stem
        if re.fullmatch(r"TA\d{4}", parts[0]):
            head = parts[0]
            tail = " ".join(w.capitalize() for w in parts[1:])
            # Ensure separator " - " between ID and name when name exists
            return (head + (" - " + tail if tail else "")).strip()
        return " ".join(w.capitalize() for w in parts)

    def flush_current():
        nonlocal current
        if current is None:
            return
        # join blocks
        current["description"] = "\n".join(current.get("description", [])).strip() or None
        current["detection"] = "\n".join(current.get("detection", [])).strip() or None
        # procedures already list of strings
        items.append(
            {
                "technique_id": current.get("id"),
                "technique_name": current.get("name"),
                "description": current.get("description"),
                "detection": current.get("detection"),
                "procedures": current.get("procedures", []) or None,
                "tactics": format_tactics(path.stem),
            }
        )
        current = None

    for raw in lines:
        if not raw.strip():
            continue

        m_sub = SECTION_SUB.match(raw)
        if m_sub:
            flush_current()
            tid = m_sub.group("id")
            full = m_sub.group("full")
            # Expect format "Parent:Sub" but fallback to full as name
            name = full
            current = {"id": tid, "name": name, "description": [], "detection": [], "procedures": [], "level": "sub"}
            mode = None
            continue

        m_parent = SECTION_PARENT.match(raw)
        if m_parent:
            flush_current()
            tid = m_parent.group("id")
            name = m_parent.group("name")
            current = {"id": tid, "name": name, "description": [], "detection": [], "procedures": [], "level": "parent"}
            mode = None
            continue

        if raw == "Description:":
            mode = "desc"
            continue
        if raw == "Detection:":
            mode = "det"
            continue
        if raw == "Procedures:":
            mode = "proc"
            continue

        if current is None:
            continue

        if mode == "proc":
            # lines like: - [G0010] Turla: text  OR  - Name: text
            line = raw.lstrip("- ").strip()
            if not line:
                continue
            current["procedures"].append(line)
        elif mode == "desc":
            current["description"].append(raw)
        elif mode == "det":
            current["detection"].append(raw)

    flush_current()
    return items


def main():
    parser = argparse.ArgumentParser(description="Parse technique Markdown files into JSON (per-file or merged)")
    parser.add_argument("inputs", nargs="+", help="Input .md files or directories containing .md")
    parser.add_argument("--outdir", default="techniques_json", help="Output directory for per-file JSON outputs")
    parser.add_argument("-o", "--output", default=None, help="If set, write ALL parsed objects into this single JSON file")
    args = parser.parse_args()

    md_files = collect_md_files(args.inputs)
    # If --output is provided, aggregate all objects into a single file
    if args.output:
        # Aggregate across files: merge by technique_id and append unique tactics
        aggregated: dict[str, dict] = {}
        for md_path in md_files:
            for obj in parse_markdown(md_path):
                tid = obj.get("technique_id")
                if not tid:
                    continue
                if tid not in aggregated:
                    entry = dict(obj)
                    tac = entry.get("tactics")
                    entry["tactics"] = [tac] if isinstance(tac, str) and tac else (tac or [])
                    aggregated[tid] = entry
                    continue

                existing = aggregated[tid]
                # merge tactics
                existing_tactics = existing.get("tactics") or []
                if isinstance(existing_tactics, str):
                    existing_tactics = [existing_tactics]
                new_tac = obj.get("tactics")
                new_tactics = [new_tac] if isinstance(new_tac, str) and new_tac else (new_tac or [])
                for tac in new_tactics:
                    if tac and tac not in existing_tactics:
                        existing_tactics.append(tac)
                existing["tactics"] = existing_tactics

                # fill missing description/detection
                for field in ["description", "detection"]:
                    if not existing.get(field) and obj.get(field):
                        existing[field] = obj[field]

                # merge procedures uniquely
                ex_procs = existing.get("procedures") or []
                new_procs = obj.get("procedures") or []
                if not ex_procs:
                    existing["procedures"] = new_procs
                elif new_procs:
                    merged = ex_procs + [p for p in new_procs if p not in ex_procs]
                    existing["procedures"] = merged

        all_objects = list(aggregated.values())
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(all_objects, f, ensure_ascii=False, indent=2)
        print(f"Saved {len(all_objects)} objects -> {out_path}")
        print(f"Done. Aggregated {len(md_files)} input file(s).")
        return

    # Otherwise, write one JSON per input .md under --outdir
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    total_objects = 0
    for md_path in md_files:
        objects = parse_markdown(md_path)
        total_objects += len(objects)
        out_path = outdir / (md_path.stem + ".json")
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(objects, f, ensure_ascii=False, indent=2)
        print(f"Saved {len(objects)} objects -> {out_path}")

    print(f"Done. Wrote {len(md_files)} files, {total_objects} objects total.")


if __name__ == "__main__":
    main()


