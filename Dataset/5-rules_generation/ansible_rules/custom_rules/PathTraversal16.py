from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class ArchiveExtractionPathTraversalRule16(AnsibleLintRule):
    id = 'SECURITY016'
    shortdesc = "Path Traversal: Potential Arbitrary File Write via Archive Extraction (Tar Slip) detected"
    description = "This code snippet may allow an attacker to perform path traversal and write files outside the intended directory."
    severity = "HIGH"
    tags = {"security", "path traversal", "archive extraction"}
    version_added = "1.0.0"

    _pattern = re.compile(r"\.extract\(.+\)")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False