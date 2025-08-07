from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class CommandInjectionRule4(AnsibleLintRule):
    id = 'SECURITY004'
    shortdesc = "Command Injection: Potential command injection vulnerability detected"
    description = "This code snippet may be vulnerable to command injection attacks."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"check_output\(")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False