from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class PasswordHashInsufficientEffortRule12(Rule):
    id = 'SECURITY012'
    shortdesc = "Use of Password Hash With Insufficient Computational Effort"
    description = "The code snippet may be using a password hash with insufficient computational effort, which can weaken security."
    severity = "HIGH"
    tags = ["security", "password", "hash"]
    version_added = "1.0.0"
    _pattern = re.compile(r"\.update\(.+\.encode\(.+?\)\)")

    def match(self, file, line: str) -> bool | str:
        if line.lstrip().startswith("#"):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
password_hash_insufficient_effort_rule12 = PasswordHashInsufficientEffortRule12