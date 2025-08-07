from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class SystemNamespacePermissionRule22(AnsibleLintRule):
    id = 'SECURITY022'
    shortdesc = "Insecure Configuration: Permission granted over system reserved namespace"
    description = "Granting permissions over system reserved namespaces can lead to security risks."
    severity = "HIGH"
    tags = {"security", "yaml"}
    version_added = "1.0.0"

    _pattern = re.compile(r"namespace: (default|kube-system)")

    def match(self, line: str) -> bool | str:
        if line.lstrip().startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False