from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class ReDoSPotentialRule17(Rule):
    id = 'SECURITY017'
    shortdesc = "Potential Regular Expression Denial of Service (ReDoS) vulnerability detected."
    description = "This rule detects potential ReDoS vulnerabilities in code that uses regular expressions."
    severity = "HIGH"
    tags = ["security", "regex", "vulnerability"]
    version_added = "1.0.0"
    _pattern = re.compile(r"(\[.*\])|(\(.*\))|(\{.*\})|(\+)|(\*)|(\?)|(\|)")

    def match(self, file, line: str) -> bool | str:
        if line.lstrip().startswith("#"):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
re_dos_potential_rule17 = ReDoSPotentialRule17