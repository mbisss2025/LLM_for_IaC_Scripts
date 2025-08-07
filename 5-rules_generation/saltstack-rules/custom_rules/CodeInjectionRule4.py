from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class CodeInjectionRule4(Rule):
    id = 'SECURITY004'
    shortdesc = "Potentially unsafe code injection using eval function."
    description = "Avoid using eval function as it can lead to code injection vulnerabilities."
    severity = "HIGH"
    tags = ["security", "code-injection"]
    version_added = "1.0.0"
    _pattern = re.compile(r".*eval\(.*\).*")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
code_injection_rule4 = CodeInjectionRule4