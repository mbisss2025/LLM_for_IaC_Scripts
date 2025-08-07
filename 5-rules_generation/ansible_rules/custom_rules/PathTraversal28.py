from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class PathTraversalRule28(AnsibleLintRule):
    id = 'SECURITY028'
    shortdesc = "Path Traversal: Potential path traversal vulnerability detected"
    description = "This code snippet may be vulnerable to path traversal attacks."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"\w+\s*=\s*\w+\[\d+\]")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False