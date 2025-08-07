from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class CodeInjectionRule2(Rule):
    id = 'SECURITY002'
    shortdesc = "Potential code injection detected"
    description = "Avoid using dynamic function calls based on user input as it can lead to code injection vulnerabilities."
    severity = "HIGH"
    tags = ["security", "code-injection"]
    version_added = "1.0.0"
    _pattern = re.compile(r"globals\(\)\[.*\]\(.*\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
code_injection_rule2 = CodeInjectionRule2