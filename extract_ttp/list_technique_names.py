import argparse
from pathlib import Path

from mitreattack.stix20 import MitreAttackData


def has_subtechniques(data: MitreAttackData, technique_stix_id: str, include_only_in_domain: bool = True) -> bool:
    """Return True if this technique has sub-techniques in the current dataset.

    include_only_in_domain: kept for future extension; currently unused since the STIX bundle
    already limits the domain (enterprise-attack.json).
    """
    subs = data.get_subtechniques_of_technique(technique_stix_id)
    return len(subs) > 0


def main():
    repo_root = Path(__file__).resolve().parents[1]
    default_stix = str(repo_root / "enterprise-attack.json")

    parser = argparse.ArgumentParser(description="List ATT&CK techniques (ID - name) to a TXT file")
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle (enterprise-attack.json)")
    parser.add_argument("--output", "-o", default="technique_names.txt", help="Output TXT file path")
    parser.add_argument(
        "--format",
        choices=["plain", "array"],
        default="plain",
        help="Output format: plain (one per line) or array (one quoted string per line ending with comma)",
    )
    args = parser.parse_args()

    data = MitreAttackData(args.stix)

    # Get all techniques (including sub-techniques), filter revoked/deprecated
    techniques = data.get_techniques(include_subtechniques=True, remove_revoked_deprecated=True)

    # Prepare selection: include all sub-techniques, and parent techniques only if they have no subs
    lines = []
    seen = set()
    for t in techniques:
        stix_id = t.get("id")
        if not stix_id or stix_id in seen:
            continue
        seen.add(stix_id)

        is_sub = t.get("x_mitre_is_subtechnique", False) is True
        if not is_sub:
            # Skip parent techniques that have sub-techniques
            if has_subtechniques(data, stix_id):
                continue

        attack_id = data.get_attack_id(stix_id) or ""
        name = t.get("name") or ""

        if is_sub:
            # Prefix with parent technique name if available
            parents = data.get_parent_technique_of_subtechnique(stix_id)
            parent_name = None
            if parents:
                parent_obj = parents[0]["object"]
                parent_name = MitreAttackData.get_field(parent_obj, "name") or ""
            full_name = f"{parent_name}: {name}" if parent_name else name
            lines.append(f"{attack_id} - {full_name}")
        else:
            lines.append(f"{attack_id} - {name}")

    # Sort by ATT&CK ID then name
    lines.sort(key=lambda s: (s.split(" - ")[0], s))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "array":
        # Each line as a quoted string with trailing comma
        array_lines = [f'"{line}",' for line in lines]
        out_path.write_text("\n".join(array_lines), encoding="utf-8")
    else:
        out_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Saved {len(lines)} techniques to {out_path}")


if __name__ == "__main__":
    main()


