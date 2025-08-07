from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class InsecureTempFileRule29(Rule):
    id = 'SECURITY029'
    shortdesc = "Insecure Temporary File"
    description = "Avoid using insecure temporary files that may expose sensitive information."
    severity = "HIGH"
    tags = ["security", "sensitive-data"]
    version_added = "1.0.0"
    _pattern = re.compile(r"tempfile\.mktemp\(\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
insecure_temp_file_rule29 = InsecureTempFileRule29