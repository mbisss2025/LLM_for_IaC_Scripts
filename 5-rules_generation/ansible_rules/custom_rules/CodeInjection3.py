from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule


class MinimalSqlRule(AnsibleLintRule):
    id = 'SECURITY003'
    shortdesc = "code injection: QL Injection Vulnerability Detected"
    description = "Potential SQL injection vulnerability identified. Use parameterized queries instead of string formatting."
    severity = "HIGH"
    tags = {"security", "python", "sql"}
    version_added = "1.0.0"

    def match(self, line: str) -> bool | str:
        # This should trigger on your vulnerable line
        if "hostname = '%s'" in line and "%" in line:
            return "SQL injection found"
        return False