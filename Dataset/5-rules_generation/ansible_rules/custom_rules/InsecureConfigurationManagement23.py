from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class WildcardPermissionsRule23(AnsibleLintRule):
    id = 'SECURITY023'
    shortdesc = "Insecure Configuration: Wildcard permissions detected"
    description = "The role uses wildcards, which grant excessive permissions."
    severity = "HIGH"
    tags = {"security", "yaml"}
    version_added = "1.0.0"

    _pattern = re.compile(r"resources:\s*\[\s*\"\*\"\s*\]")

    def match(self, line: str) -> bool | str:
        if line.lstrip().startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False