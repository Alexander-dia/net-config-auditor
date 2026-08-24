import json
import re
from pathlib import Path

class ConfigAuditor:
    def __init__(self, rules_path: str = "rules/compliance_rules.json"):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()

    def _load_rules(self) -> list:
        if not self.rules_path.exists():
            raise FileNotFoundError(f"Rules file not found at: {self.rules_path}")
        with open(self.rules_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def audit_file(self, config_path: str) -> dict:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found at: {config_path}")

        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith("!")]

        full_text = "\n".join(lines)
        results = []
        passed_count = 0

        for rule in self.rules:
            rule_id = rule["id"]
            title = rule["title"]
            severity = rule["severity"]
            desc = rule["description"]
            remediation = rule["remediation"]

            passed = False
            details = ""

            # Kontroll 1: Krav på att ett mönster MÅSTE finnas
            if "pattern_required" in rule:
                pattern = rule["pattern_required"]
                match = re.search(pattern, full_text, re.MULTILINE | re.IGNORECASE)
                if match:
                    passed = True
                    details = f"Required pattern '{pattern}' found."
                else:
                    passed = False
                    details = f"Missing required configuration pattern: '{pattern}'"

            # Kontroll 2: Krav på att ett förbjudet mönster INTE får finnas
            elif "pattern_forbidden" in rule:
                pattern = rule["pattern_forbidden"]
                match = re.search(pattern, full_text, re.MULTILINE | re.IGNORECASE)
                if match:
                    passed = False
                    details = f"Forbidden pattern detected: '{match.group(0)}'"
                else:
                    passed = True
                    details = f"Forbidden pattern '{pattern}' not present."

            if passed:
                passed_count += 1

            results.append({
                "id": rule_id,
                "title": title,
                "severity": severity,
                "description": desc,
                "passed": passed,
                "details": details,
                "remediation": remediation
            })

        total_rules = len(self.rules)
        score = int((passed_count / total_rules) * 100) if total_rules > 0 else 0

        return {
            "target_file": str(path.name),
            "total_rules": total_rules,
            "passed": passed_count,
            "failed": total_rules - passed_count,
            "score": score,
            "findings": results
        }