from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class ImagePolicyRule24(AnsibleLintRule):
    id = 'SECURITY024'
    shortdesc = "Insecure Configuration: Image policy does not prevent image reuse"
    description = "The image policy should be set to prevent image reuse for security reasons."
    severity = "HIGH"
    tags = {"security", "yaml"}
    version_added = "1.0.0"

    _pattern = re.compile(r"image:.*")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            if "imagePullPolicy" not in line:
                return self.shortdesc
        return False