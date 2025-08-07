from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class ReDoSPotentialRule20(Rule):
    id = 'SECURITY020'
    shortdesc = "Potential Regular Expression Denial of Service (ReDoS) vulnerability detected."
    description = "Avoid using user-controlled input directly in regular expressions to prevent ReDoS attacks."
    severity = "HIGH"
    tags = ["security", "regex", "reDos"]
    version_added = "1.0.0"
    _pattern = re.compile(r"re\.compile\(.+\)")

    def match(self, file, line: str) -> bool | str:
        if line.lstrip().startswith("#"):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
re_dos_potential_rule20 = ReDoSPotentialRule20