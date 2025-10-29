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


def build_tactic_to_techniques(data: MitreAttackData, domain: str, exclude_subtech: bool = False, full_name: bool = False) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    tactics = get_tactics_in_order(data, domain)

    for tactic in tactics:
        shortname = MitreAttackData.get_field(tactic, "x_mitre_shortname")
        tactic_stix_id = MitreAttackData.get_field(tactic, "id") or ""
        tactic_id = data.get_attack_id(tactic_stix_id) or tactic_stix_id
        
        if full_name:
            tactic_name = MitreAttackData.get_field(tactic, "name") or ""
            tactic_key = f"{tactic_id} - {tactic_name}" if tactic_id else tactic_name
        else:
            tactic_key = tactic_id

        techniques = data.get_techniques_by_tactic(shortname, domain, remove_revoked_deprecated=True)

        selected_attack_ids: list[str] = []
        for tech in techniques:
            stix_id = MitreAttackData.get_field(tech, "id")
            
            if exclude_subtech:
                is_sub = bool(MitreAttackData.get_field(tech, "x_mitre_is_subtechnique", False))
                if is_sub:
                    continue  # Skip sub-techniques only
            
            attack_id = data.get_attack_id(stix_id) or stix_id
            
            if full_name:
                tech_name = MitreAttackData.get_field(tech, "name") or ""
                is_sub = bool(MitreAttackData.get_field(tech, "x_mitre_is_subtechnique", False))
                
                if is_sub:
                    # For sub-techniques, format as "Parent: Sub" like get_techniques_of_tactic.py
                    parents = data.get_parent_technique_of_subtechnique(stix_id)
                    if parents:
                        parent_obj = parents[0]["object"]
                        parent_name = MitreAttackData.get_field(parent_obj, "name") or ""
                        full_tech_name = f"{parent_name}: {tech_name}" if parent_name else tech_name
                    else:
                        full_tech_name = tech_name
                    entry = f"{attack_id} - {full_tech_name}" if attack_id else full_tech_name
                else:
                    # For parent techniques, just use the name
                    entry = f"{attack_id} - {tech_name}" if attack_id else tech_name
                selected_attack_ids.append(entry)
            else:
                selected_attack_ids.append(attack_id)

        # sort by ATT&CK ID then value
        selected_attack_ids = sorted(selected_attack_ids)
        mapping[tactic_key] = selected_attack_ids

    return mapping


def build_technique_to_tactics(data: MitreAttackData, domain: str, exclude_subtech: bool = False, full_name: bool = False) -> dict[str, list[str]]:
    mapping_sets: dict[str, set[str]] = {}
    tactics = get_tactics_in_order(data, domain)

    for tactic in tactics:
        shortname = MitreAttackData.get_field(tactic, "x_mitre_shortname")
        tactic_stix_id = MitreAttackData.get_field(tactic, "id") or ""
        tactic_id = data.get_attack_id(tactic_stix_id) or tactic_stix_id
        
        if full_name:
            tactic_name = MitreAttackData.get_field(tactic, "name") or ""
            tactic_key = f"{tactic_id} - {tactic_name}" if tactic_id else tactic_name
        else:
            tactic_key = tactic_id

        techniques = data.get_techniques_by_tactic(shortname, domain, remove_revoked_deprecated=True)

        for tech in techniques:
            stix_id = MitreAttackData.get_field(tech, "id")
            
            if exclude_subtech:
                is_sub = bool(MitreAttackData.get_field(tech, "x_mitre_is_subtechnique", False))
                if is_sub:
                    continue  # Skip sub-techniques only
            
            attack_id = data.get_attack_id(stix_id) or stix_id
            
            if full_name:
                tech_name = MitreAttackData.get_field(tech, "name") or ""
                is_sub = bool(MitreAttackData.get_field(tech, "x_mitre_is_subtechnique", False))
                
                if is_sub:
                    # For sub-techniques, format as "Parent: Sub" like get_techniques_of_tactic.py
                    parents = data.get_parent_technique_of_subtechnique(stix_id)
                    if parents:
                        parent_obj = parents[0]["object"]
                        parent_name = MitreAttackData.get_field(parent_obj, "name") or ""
                        full_tech_name = f"{parent_name}: {tech_name}" if parent_name else tech_name
                    else:
                        full_tech_name = tech_name
                    key = f"{attack_id} - {full_tech_name}" if attack_id else full_tech_name
                else:
                    # For parent techniques, just use the name
                    key = f"{attack_id} - {tech_name}" if attack_id else tech_name
            else:
                key = attack_id
                
            if key not in mapping_sets:
                mapping_sets[key] = set()
            mapping_sets[key].add(tactic_key)

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
    parser.add_argument(
        "--exclude-subtech",
        action="store_true",
        help="Exclude sub-techniques, keep parent techniques (even if they have sub-techniques)",
    )
    parser.add_argument(
        "--full-name",
        action="store_true",
        help="Include full technique names in format 'ID - Name' (sub-techniques as 'ID - Parent: Sub')",
    )
    parser.add_argument("--output", "-o", default="mitre_dictionary.json", help="Output JSON file path")
    args = parser.parse_args()

    data = MitreAttackData(args.stix)

    if args.mapping == "tactic-to-techniques":
        result = build_tactic_to_techniques(data, args.domain, args.exclude_subtech, args.full_name)
    else:
        result = build_technique_to_tactics(data, args.domain, args.exclude_subtech, args.full_name)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(__import__("json").dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Saved mapping '{args.mapping}' with {len(result)} keys to {out_path}")


if __name__ == "__main__":
    main()


