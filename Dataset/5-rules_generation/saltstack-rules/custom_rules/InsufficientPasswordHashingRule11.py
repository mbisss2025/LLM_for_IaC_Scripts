from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class InsufficientPasswordHashingRule11(Rule):
    id = 'SECURITY011'
    shortdesc = "Use of Password Hash With Insufficient Computational Effort"
    description = "The code snippet contains the use of password hash with insufficient computational effort, which can lead to security vulnerabilities."
    severity = "HIGH"
    tags = ["security", "password", "hashing"]
    version_added = "1.0.0"
    _pattern = re.compile(r"hashlib\.sha1\(.+\)\.hexdigest\(\)")

    def match(self, file, line: str) -> bool | str:
        if line.lstrip().startswith("#"):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
insufficient_password_hashing_rule11 = InsufficientPasswordHashingRule11