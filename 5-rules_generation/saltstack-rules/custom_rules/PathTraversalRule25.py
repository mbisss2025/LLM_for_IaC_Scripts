from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class PathTraversalRule25(Rule):
    id = 'SECURITY025'
    shortdesc = "Potential Path Traversal Vulnerability"
    description = "This rule detects potential path traversal vulnerabilities in the code."
    severity = "HIGH"
    tags = ["security", "path_traversal"]
    version_added = "1.0.0"
    _pattern = re.compile(r"os\.path\.join\([^\)]+\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
path_traversal_rule25 = PathTraversalRule25