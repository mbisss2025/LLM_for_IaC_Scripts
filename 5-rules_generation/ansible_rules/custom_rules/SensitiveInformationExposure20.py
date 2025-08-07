from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class HardcodedSecretRule20(AnsibleLintRule):
    id = 'SECURITY020'
    shortdesc = "Sensitive Information Exposure: Hardcoded secret detected"
    description = "Hardcoding secrets in code can lead to security vulnerabilities."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"access_id=|secret_key=")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False