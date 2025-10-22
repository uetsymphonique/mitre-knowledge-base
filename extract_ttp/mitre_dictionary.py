import argparse
from pathlib import Path

from mitreattack.stix20 import MitreAttackData


def get_tactics_in_order(data: MitreAttackData, domain: str):
    tactics_by_matrix = data.get_tactics_by_matrix()
    for matrix_name, tactics in tactics_by_matrix.items():
        if domain.split("-")[0] in matrix_name.lower():
            return tactics
    # Fallback: all tactics filtered by domain
    tactics = data.get_tactics(remove_revoked_deprecated=True)
    filtered = []
    for t in tactics:
        domains = MitreAttackData.get_field(t, "x_mitre_domains") or []
        if domain in domains:
            filtered.append(t)
    return filtered


def build_tactic_to_techniques(data: MitreAttackData, domain: str) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    tactics = get_tactics_in_order(data, domain)

    for tactic in tactics:
        shortname = MitreAttackData.get_field(tactic, "x_mitre_shortname")
        tactic_id = data.get_attack_id(MitreAttackData.get_field(tactic, "id") or "") or (
            MitreAttackData.get_field(tactic, "id") or ""
        )

        techniques = data.get_techniques_by_tactic(shortname, domain, remove_revoked_deprecated=True)
        technique_ids_in_tactic = {MitreAttackData.get_field(t, "id") for t in techniques}

        selected_attack_ids: list[str] = []
        for tech in techniques:
            stix_id = MitreAttackData.get_field(tech, "id")
            is_sub = bool(MitreAttackData.get_field(tech, "x_mitre_is_subtechnique", False))
            if not is_sub:
                # Exclude parent if it has sub-techniques present in this tactic
                subs = data.get_subtechniques_of_technique(stix_id)
                subs_in_tactic = [
                    e for e in subs if e.get("object") and e["object"]["id"] in technique_ids_in_tactic
                ]
                if subs_in_tactic:
                    continue

            attack_id = data.get_attack_id(stix_id) or stix_id
            selected_attack_ids.append(attack_id)

        # sort by ATT&CK ID then value
        selected_attack_ids = sorted(selected_attack_ids)
        mapping[tactic_id] = selected_attack_ids

    return mapping


def build_technique_to_tactics(data: MitreAttackData, domain: str) -> dict[str, list[str]]:
    mapping_sets: dict[str, set[str]] = {}
    tactics = get_tactics_in_order(data, domain)

    for tactic in tactics:
        shortname = MitreAttackData.get_field(tactic, "x_mitre_shortname")
        tactic_id = data.get_attack_id(MitreAttackData.get_field(tactic, "id") or "") or (
            MitreAttackData.get_field(tactic, "id") or ""
        )

        techniques = data.get_techniques_by_tactic(shortname, domain, remove_revoked_deprecated=True)
        technique_ids_in_tactic = {MitreAttackData.get_field(t, "id") for t in techniques}

        for tech in techniques:
            stix_id = MitreAttackData.get_field(tech, "id")
            is_sub = bool(MitreAttackData.get_field(tech, "x_mitre_is_subtechnique", False))
            if not is_sub:
                subs = data.get_subtechniques_of_technique(stix_id)
                subs_in_tactic = [
                    e for e in subs if e.get("object") and e["object"]["id"] in technique_ids_in_tactic
                ]
                if subs_in_tactic:
                    continue

            attack_id = data.get_attack_id(stix_id) or stix_id
            if attack_id not in mapping_sets:
                mapping_sets[attack_id] = set()
            mapping_sets[attack_id].add(tactic_id)

    # Convert sets to sorted lists
    return {tech_id: sorted(list(tactic_ids)) for tech_id, tactic_ids in mapping_sets.items()}


def main():
    repo_root = Path(__file__).resolve().parents[1]
    default_stix = str(repo_root / "enterprise-attack.json")

    parser = argparse.ArgumentParser(description="Build MITRE ATT&CK dictionaries (IDs only)")
    parser.add_argument("--stix", default=default_stix, help="Path to ATT&CK STIX bundle (enterprise-attack.json)")
    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        choices=["enterprise-attack", "mobile-attack", "ics-attack"],
        help="ATT&CK domain",
    )
    parser.add_argument(
        "--mapping",
        required=True,
        choices=["tactic-to-techniques", "technique-to-tactics"],
        help="Mapping direction to generate",
    )
    parser.add_argument("--output", "-o", default="mitre_dictionary.json", help="Output JSON file path")
    args = parser.parse_args()

    data = MitreAttackData(args.stix)

    if args.mapping == "tactic-to-techniques":
        result = build_tactic_to_techniques(data, args.domain)
    else:
        result = build_technique_to_tactics(data, args.domain)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(__import__("json").dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Saved mapping '{args.mapping}' with {len(result)} keys to {out_path}")


if __name__ == "__main__":
    main()


