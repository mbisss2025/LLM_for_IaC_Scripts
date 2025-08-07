from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class ExcessiveContainerPortsRule7(AnsibleLintRule):
    id = 'SECURITY007'
    shortdesc = "Insecure Configuration: Excessive container ports declared"
    description = "Containers should not declare more than 2 listening ports for security reasons."
    severity = "HIGH"
    tags = {"security", "yaml"}
    version_added = "1.0.0"

    _pattern = re.compile(r"^\s+-\s+containerPort:")

    def match(self, line: str) -> bool | str:
        if line.lstrip().startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False