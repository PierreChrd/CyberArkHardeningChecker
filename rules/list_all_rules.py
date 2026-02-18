import os
import json
import csv

RULES_ROOT = "./rules"
CSV_OUTPUT = "./rules/rules_export.csv"

def list_rule_files(root):
    rule_files = []
    for base, dirs, files in os.walk(root):
        for f in files:
            if f.lower().endswith(".json"):
                full_path = os.path.join(base, f)
                rule_files.append(full_path)
    return rule_files

def load_rule(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[Error] Impossible to read {file_path} : {e}")
        return None

def normalize_rule(rule, file_path):
    return {
        "file": file_path,
        "id": rule.get("id"),
        "title": rule.get("title"),
        "description": rule.get("description"),
        "type": rule.get("type"),
        "appliesTo": ",".join(rule.get("appliesTo", [])),
        "severity": rule.get("severity"),
        "tags": ",".join(rule.get("tags", [])),

        "serviceName": rule.get("serviceName", ""),
        "expectedStatus": rule.get("expectedStatus", ""),
        "command": rule.get("command", ""),
        "expected": rule.get("expected", ""),
        "path": rule.get("path", ""),
        "operator": rule.get("operator", "")
    }

def export_csv(normalized_rules, output_file):
    if not normalized_rules:
        print("[INFO] No rules founded, aborting CSV generation...")
        return

    fieldnames = list(normalized_rules[0].keys())

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(normalized_rules)

    print(f"[OK] CSV export ended : {output_file}")


if __name__ == "__main__":
    print("-----------------------------------------------------")
    print("      CyberArk Hardening – Rules Export")
    print("-----------------------------------------------------")

    rule_files = list_rule_files(RULES_ROOT)

    print(f"[INFO] Rules files founded : {len(rule_files)}")

    all_rules = []
    for file_path in rule_files:
        rule_json = load_rule(file_path)
        if rule_json:
            norm = normalize_rule(rule_json, file_path)
            all_rules.append(norm)

    print("\n======= RULES LIST =======")
    for r in all_rules:
        print(f"- {r['id']} | {r['title']} | {r['type']} | {r['appliesTo']}")
    print("============================\n")

    export_csv(all_rules, CSV_OUTPUT)