from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class CommandInjectionRule9(Rule):
    id = 'SECURITY009'
    shortdesc = "Possible command injection detected."
    description = "Avoid using subprocess.Popen with untrusted input to prevent command injection vulnerabilities."
    severity = "HIGH"
    tags = ["security", "command_injection"]
    version_added = "1.0.0"
    _pattern = re.compile(r"subprocess\.Popen\(.+\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            if "filename=" in line and "args=" in line:
                return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
command_injection_rule9 = CommandInjectionRule9