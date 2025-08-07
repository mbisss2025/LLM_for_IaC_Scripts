from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class InsecureTempFileRule27(Rule):
    id = 'SECURITY027'
    shortdesc = "Insecure Temporary File"
    description = "Avoid using insecure temporary files that can expose sensitive information."
    severity = "HIGH"
    tags = ["security", "sensitive_information"]
    version_added = "1.0.0"
    _pattern = re.compile(r"\btempfile\.mktemp\(\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
insecure_temp_file_rule27 = InsecureTempFileRule27