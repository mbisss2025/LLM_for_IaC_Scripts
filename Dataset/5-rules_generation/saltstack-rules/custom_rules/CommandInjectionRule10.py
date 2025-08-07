from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class CommandInjectionRule10(Rule):
    id = 'SECURITY010'
    shortdesc = "Possible command injection detected."
    description = "Avoid using unsanitized user input in subprocess calls to prevent command injection vulnerabilities."
    severity = "HIGH"
    tags = ["security", "command_injection"]
    version_added = "1.0.0"
    _pattern = re.compile(r"\b(subprocess\.call\(|subprocess\.check_call\(|subprocess\.check_output\()")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
command_injection_rule10 = CommandInjectionRule10