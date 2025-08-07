from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class HardcodedCredentialsRule19(AnsibleLintRule):
    id = 'SECURITY019'
    shortdesc = "Sensitive Information Exposure: Hardcoded credentials detected"
    description = "Hardcoding credentials in code can lead to security vulnerabilities."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"'password':\s*'.+'")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False