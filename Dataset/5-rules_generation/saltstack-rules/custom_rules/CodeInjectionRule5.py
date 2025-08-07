from __future__ import annotations
import re
from saltlint.linter.rule import Rule


class CodeInjectionRule5(Rule):
    id = "SECURITY005"
    short = "Security Smell [Code Injection]: import dynamique dangereux"
    description = (
        "L'utilisation d'importlib.import_module() ou de __import__() avec un "
        "nom de module issu d'une variable/entrée utilisateur peut charger du "
        "code arbitraire. Préférez un mapping statique ou une liste blanche."
    )
    severity = "HIGH"
    tags = ["security", "code-injection", "python"]
    version_added = "1.0.0"
    version_changed = "1.0.0"          # gardé pour respecter votre convention

    _regex = re.compile(r"(?:importlib\.import_module|__import__)\s*\(")

    # salt-lint appelle match(file, line) pour chaque ligne
    def match(self, file, line: str):  # signature correcte : file, line
        # Ne scanner que les fichiers Python (.py)
        if not str(file["path"]).endswith(".py"):
            return False

        # Si la ligne correspond au pattern → retourne short-desc, sinon False
        return self.short if self._regex.search(line) else False
