from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class CodeInjectionRule3(Rule):
    id = 'SECURITY003'
    shortdesc = "Potentially unsafe use of eval function."
    description = "Avoid using eval function as it can lead to code injection vulnerabilities."
    severity = "HIGH"
    tags = ["security", "code-injection"]
    version_added = "1.0.0"
    _pattern = re.compile(r"eval\(")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
code_injection_rule3 = CodeInjectionRule3