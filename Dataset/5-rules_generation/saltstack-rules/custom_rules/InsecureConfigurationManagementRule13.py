from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class InsecureConfigurationManagementRule13(Rule):
    id = "SECURITY013"
    short = "Security Smell [Weak Hash]: SHA-1 utilisé"
    description = (
        "SHA-1 (hashlib.sha1 / sha1) n’offre pas assez d’effort de calcul "
        "pour protéger des mots de passe ; utilisez bcrypt, scrypt ou Argon2."
    )
    severity = "HIGH"
    tags = ["security", "weak-hash", "python"]
    version_added = "1.0.0"
    version_changed = "1.0.0"

    # regex : hashlib.sha1( … )  ou  sha1( … )
    _rx = re.compile(r"\b(?:hashlib\.)?sha1\s*\(", re.I)

    # salt-lint appelle match(file, line) pour chaque ligne
    def match(self, file, line: str):  # noqa: D401
        # Cibler seulement les fichiers Python
        if not str(file["path"]).endswith(".py"):
            return False
        return self.short if self._rx.search(line) else False
