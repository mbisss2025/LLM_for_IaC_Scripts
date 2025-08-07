from __future__ import annotations
import re
from saltlint.linter.rule import Rule


class CommandInjectionRule8(Rule):
    id = "SECURITY008"
    short = "Security Smell [Command Injection]: subprocess.getoutput"
    description = (
        "L'appel à subprocess.getoutput() exécute une commande shell et "
        "peut conduire à une injection si la chaîne est construite avec "
        "des données non filtrées."
    )
    severity = "HIGH"
    tags = ["security", "command-injection", "python"]
    version_added = "1.0.0"
    version_changed = "1.0.0"

    # simple détection : recherche 'subprocess.getoutput(' dans la ligne
    _regex = re.compile(r"subprocess\.getoutput\s*\(")

    # salt-lint appelle match(file, line) pour chaque ligne
    def match(self, file, line: str):  # noqa: D401
        # ne scanner que les fichiers .py
        if not str(file["path"]).endswith(".py"):
            return False

        return self.short if self._regex.search(line) else False
