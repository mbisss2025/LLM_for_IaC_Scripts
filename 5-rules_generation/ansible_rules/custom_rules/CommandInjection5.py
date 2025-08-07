from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class CommandInjectionRule5(AnsibleLintRule):
    id = 'SECURITY005'
    shortdesc = "Command Injection: Potential command injection detected"
    description = "This code snippet may be vulnerable to command injection."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r".*\b(?:os.system|subprocess.call|subprocess.Popen|shell=True)\b.*")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if self._pattern.search(line_stripped):
            return self.shortdesc
        return False