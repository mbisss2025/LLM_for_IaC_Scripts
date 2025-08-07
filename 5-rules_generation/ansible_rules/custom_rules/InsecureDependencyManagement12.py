from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class ImagePolicyViolationRule12(AnsibleLintRule):
    id = 'SECURITY012'
    shortdesc = "Insecure Dependency Management: Container images should not use 'latest' tag."
    description = "Container images should use specific version tags instead of 'latest"
    severity = "HIGH"
    tags = {"security", "yaml"}
    version_added = "1.0.0"

    _pattern = re.compile(r"^\s*image:\s*.+:latest\s*$")

    def match(self, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False