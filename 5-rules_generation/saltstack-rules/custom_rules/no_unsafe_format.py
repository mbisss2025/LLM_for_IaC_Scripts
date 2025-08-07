# custom_rules/no_unsafe_format.py
from __future__ import annotations
import re
from saltlint.linter.rule import Rule


class NoUnsafeFormatRule(Rule):
    id = "SIC001"
    shortdesc = "Possible code-injection via str.format()"
    severity = "HIGH"
    tags = ["security"]
    version_added = "1.0.0"
    version_changed = "1.0.0"
    _pattern = re.compile(r"\.format\s*\(", re.I)

    def match(self, file, line: str) -> bool | str:
        if line.lstrip().startswith("#"):
            return False
        return self.shortdesc if self._pattern.search(line) else False


# ──────────────────────────────────────────────────────────
#  ALIAS pour que le loader « voie » la classe :
#  le nom à gauche DOIT être identique au nom du fichier.
# ──────────────────────────────────────────────────────────
no_unsafe_format = NoUnsafeFormatRule
