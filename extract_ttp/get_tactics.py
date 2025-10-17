import argparse
from pathlib import Path

from mitreattack.stix20 import MitreAttackData


def extract_tactics(stix_path: str, domain: str, include_revoked_deprecated: bool) -> list[dict]:
    data = MitreAttackData(stix_path)

    # When include_revoked_deprecated=False, we remove revoked/deprecated
    tactics = data.get_tactics(remove_revoked_deprecated=not include_revoked_deprecated)

    # Filter by domain if provided
    if domain:
        filtered = []
        for t in tactics:
            domains = MitreAttackData.get_field(t, "x_mitre_domains") or []
            if domain in domains:
                filtered.append(t)
        tactics = filtered

    results = []
    for tactic in tactics:
        name = MitreAttackData.get_field(tactic, "name")
        description = (MitreAttackData.get_field(tactic, "description") or "").strip()
        stix_id = MitreAttackData.get_field(tactic, "id")
        attack_id = data.get_attack_id(stix_id) or None
        results.append({"name": name, "attack_id": attack_id, "description": description})

    # Sort by ATT&CK ID then name for consistent output
    results.sort(key=lambda x: (x["attack_id"] or "", x["name"] or ""))
    return results


def _escape_md(text: str) -> str:
    if text is None:
        return ""
    # Keep newlines for readability and chunking; trim surrounding whitespace
    return str(text).strip()


def to_markdown(tactics: list[dict], domain: str) -> str:
    lines = []
    lines.append(f"## ATT&CK Tactics - {domain}")
    lines.append("")
    lines.append(f"Total: {len(tactics)}")
    lines.append("")
    for t in tactics:
        attack_id = _escape_md(t.get("attack_id") or "")
        name = _escape_md(t.get("name") or "")
        description = _escape_md(t.get("description") or "")

        # Section header includes ID and name for easy chunking
        if attack_id:
            lines.append(f"### {attack_id} - {name}")
        else:
            lines.append(f"### {name}")
        lines.append("")
        lines.append(description)
        lines.append("")
    return "\n".join(lines)


def main():
    repo_root = Path(__file__).resolve().parents[1]
    default_stix = str(repo_root / "enterprise-attack.json")

    parser = argparse.ArgumentParser(description="Export ATT&CK tactics to Markdown")
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle (enterprise-attack.json)")
    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        help="ATT&CK domain to include",
    )
    parser.add_argument("--output", "-o", default="tactics.md", help="Output Markdown file path")
    parser.add_argument(
        "--include-revoked-deprecated",
        action="store_true",
        help="Include revoked/deprecated tactics in output",
    )
    args = parser.parse_args()

    data = extract_tactics(
        stix_path=args.stix,
        domain=args.domain,
        include_revoked_deprecated=args.include_revoked_deprecated,
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = to_markdown(data, args.domain)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(content)

    print(f"Saved {len(data)} tactics (Markdown) to {out_path}")


if __name__ == "__main__":
    main()


