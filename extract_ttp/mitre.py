from mitreattack.stix20 import MitreAttackData


def main():
    data = MitreAttackData("enterprise-attack.json")

    # Prefer tactics as ordered in the Enterprise matrix
    tactics_by_matrix = data.get_tactics_by_matrix()
    enterprise_tactics = None
    for matrix_name, tactics in tactics_by_matrix.items():
        if "enterprise" in matrix_name.lower():
            enterprise_tactics = tactics
            break

    # Fallback to all tactics if Enterprise matrix is not found
    if not enterprise_tactics:
        enterprise_tactics = data.get_tactics(remove_revoked_deprecated=True)

    for tactic in enterprise_tactics:
        tactic_name = MitreAttackData.get_field(tactic, "name")
        shortname = MitreAttackData.get_field(tactic, "x_mitre_shortname")
        if shortname is None and hasattr(tactic, "get_shortname"):
            shortname = tactic.get_shortname()

        techniques = data.get_techniques_by_tactic(
            shortname, "enterprise-attack", remove_revoked_deprecated=True
        )

        print(f"{tactic_name} ({shortname}) - {len(techniques)} techniques")

        # Separate parent techniques and sub-techniques
        technique_ids = {MitreAttackData.get_field(t, "id") for t in techniques}
        parent_techniques = [
            t for t in techniques if not MitreAttackData.get_field(t, "x_mitre_is_subtechnique", False)
        ]

        # Sort parents by ATT&CK ID for readability
        def get_attack_id_or_empty(t):
            tid = MitreAttackData.get_field(t, "id")
            return data.get_attack_id(tid) or ""

        parent_techniques.sort(key=lambda t: (get_attack_id_or_empty(t), MitreAttackData.get_field(t, "name") or ""))

        printed_sub_ids = set()

        for parent in parent_techniques:
            parent_name = MitreAttackData.get_field(parent, "name")
            parent_id = MitreAttackData.get_field(parent, "id")
            parent_attack_id = data.get_attack_id(parent_id) or ""

            if parent_attack_id:
                print(f"  - {parent_attack_id}: {parent_name}")
            else:
                print(f"  - {parent_name}")

            # Fetch sub-techniques of this parent and keep only those in this tactic
            sub_entries = data.get_subtechniques_of_technique(parent_id)
            sub_techniques = [e["object"] for e in sub_entries if e.get("object") and e["object"]["id"] in technique_ids]

            # Sort subs by ATT&CK ID
            sub_techniques.sort(key=lambda s: (data.get_attack_id(MitreAttackData.get_field(s, "id")) or "", MitreAttackData.get_field(s, "name") or ""))

            for sub in sub_techniques:
                sub_name = MitreAttackData.get_field(sub, "name")
                sub_id = MitreAttackData.get_field(sub, "id")
                sub_attack_id = data.get_attack_id(sub_id) or ""
                printed_sub_ids.add(sub_id)
                if sub_attack_id:
                    print(f"    - {sub_attack_id}: {sub_name}")
                else:
                    print(f"    - {sub_name}")

        # Handle orphan sub-techniques (if any) that didn't resolve to a parent
        orphan_subs = [
            t
            for t in techniques
            if MitreAttackData.get_field(t, "x_mitre_is_subtechnique", False)
            and MitreAttackData.get_field(t, "id") not in printed_sub_ids
        ]

        if orphan_subs:
            print("    - (sub-techniques without resolved parent):")
            orphan_subs.sort(key=lambda s: (data.get_attack_id(MitreAttackData.get_field(s, "id")) or "", MitreAttackData.get_field(s, "name") or ""))
            for sub in orphan_subs:
                sub_name = MitreAttackData.get_field(sub, "name")
                sub_id = MitreAttackData.get_field(sub, "id")
                sub_attack_id = data.get_attack_id(sub_id) or ""
                if sub_attack_id:
                    print(f"      - {sub_attack_id}: {sub_name}")
                else:
                    print(f"      - {sub_name}")


if __name__ == "__main__":
    main()