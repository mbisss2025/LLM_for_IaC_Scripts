from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class PathTraversalDetectionRule18(AnsibleLintRule):
    id = 'SECURITY018'
    shortdesc = "Path Traversal Vulnerability Detected"
    description = "Potential path traversal vulnerability identified in the code."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"\.+\s*\w+\(")  # Detects patterns like ".. function_name("

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False