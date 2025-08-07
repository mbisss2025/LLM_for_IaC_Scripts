from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class MemoryLimitNotDefinedRule11(AnsibleLintRule):
    id = 'SECURITY011'
    shortdesc = "Insecure Dependency Management: no specific version tags"
    description = "Container images should use specific version tags."
    severity = "HIGH"
    tags = {"security", "yaml"}
    version_added = "1.0.0"

    _pattern = re.compile(r"^\s*image:\s*[\"']?([^\"'\s]+)(?![:\"])[\"']?\s*$")

    def match(self, line: str) -> bool | str:
        if line.lstrip().startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False