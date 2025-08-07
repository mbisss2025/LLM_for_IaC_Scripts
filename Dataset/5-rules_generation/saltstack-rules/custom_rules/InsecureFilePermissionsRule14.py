from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class InsecureFilePermissionsRule14(Rule):
    id = 'SECURITY014'
    shortdesc = "Insecure file permissions detected"
    description = "Avoid using insecure file permissions (e.g., 777) in code."
    severity = "HIGH"
    tags = ["security", "permissions"]
    version_added = "1.0.0"
    _pattern = re.compile(r"os\.chmod\(.+?,\s*0o777\)")

    def match(self, file, line: str) -> bool | str:
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
insecure_file_permissions_rule14 = InsecureFilePermissionsRule14