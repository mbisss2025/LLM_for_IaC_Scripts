from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class InsecureTempFileRule28(Rule):
    id = 'SECURITY028'
    shortdesc = "Insecure Temporary File"
    description = "Avoid using insecure temporary files that may expose sensitive information."
    severity = "HIGH"
    tags = ["security", "sensitive-data"]
    version_added = "1.0.0"
    _pattern = re.compile(r"\btempfile\.mktemp\(")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
insecure_temp_file_rule28 = InsecureTempFileRule28