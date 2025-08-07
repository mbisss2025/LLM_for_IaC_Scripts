from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class PathTraversalRule23(Rule):
    id = 'SECURITY023'
    shortdesc = "Potential Path Traversal Vulnerability detected."
    description = "This code may be vulnerable to Path Traversal attack."
    severity = "HIGH"
    tags = ["security", "path_traversal"]
    version_added = "1.0.0"
    _pattern = re.compile(r"open\(.+?, 'w'\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            if "output_spec_path" in line:
                return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
path_traversal_rule23 = PathTraversalRule23