from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class UntrustedDeserializationRule2(AnsibleLintRule):
    id = 'SECURITY002'
    shortdesc = "Code Injection: Deserialization of Untrusted Data detected"
    description = "Deserializing untrusted data can lead to security vulnerabilities."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"yaml\.load\(.+, Loader=")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False