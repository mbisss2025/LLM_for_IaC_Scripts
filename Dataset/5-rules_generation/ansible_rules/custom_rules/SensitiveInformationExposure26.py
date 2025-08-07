from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class HardcodedSecretRule26(AnsibleLintRule):
    id = 'SECURITY026'
    shortdesc = "Sensitive Information Exposure: Hardcoded secret detected"
    description = "This code contains a hardcoded secret that can lead to security vulnerabilities."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"API_KEY")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False