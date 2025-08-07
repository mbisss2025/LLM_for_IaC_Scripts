from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class PathTraversalRule22(Rule):
    id = 'SECURITY022'
    shortdesc = "Potential Path Traversal Vulnerability"
    description = "This code snippet may be vulnerable to path traversal attacks by directly using user input in file operations."
    severity = "HIGH"
    tags = ["security", "path_traversal"]
    version_added = "1.0.0"
    _pattern = re.compile(r"open\(\s*sys\.argv\[\s*\d+\s*\]")

    def match(self, file, line: str) -> bool | str:
        if line.lstrip().startswith("#"):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
path_traversal_rule22 = PathTraversalRule22