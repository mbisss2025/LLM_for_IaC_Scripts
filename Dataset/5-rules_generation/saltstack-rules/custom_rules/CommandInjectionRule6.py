from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class CommandInjectionRule6(Rule):
    id = 'SECURITY006'
    shortdesc = "Possible command injection detected."
    description = "Avoid using shell=True with subprocess.Popen to prevent command injection vulnerabilities."
    severity = "HIGH"
    tags = ["security", "command_injection"]
    version_added = "1.0.0"
    _pattern = re.compile(r"\bPopen\(.+, shell=True\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
command_injection_rule6 = CommandInjectionRule6