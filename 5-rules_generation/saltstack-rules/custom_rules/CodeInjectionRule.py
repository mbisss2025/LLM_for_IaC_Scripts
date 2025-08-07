from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class CodeInjectionRule(Rule):
    id = "SECURITY_test"
    shortdesc = "Potential code injection detected."
    description = "This line may be vulnerable to code injection."
    severity = "HIGH"
    tags = ["security", "code-injection"]
    version_added = "1.0.0"
    _pattern = re.compile(r".*\w+\.\w+\(.*\).*")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
code_injection_rule = CodeInjectionRule