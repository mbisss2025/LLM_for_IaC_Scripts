# custom_rules/unsafe_format_python.py
from __future__ import annotations
import re
from saltlint.linter.rule import Rule
from typing import List


class CodeInjectionRule1(Rule):
    id = "SECURITY001"
    short = "Unsafe string formatting (str.format / %)"
    description = (
        "L'utilisation de str.format() ou de l'opérateur % pour interpoler "
        "des variables peut mener à des injections. Préférez les f-strings "
        "ou la concaténation contrôlée."
    )
    severity = "HIGH"
    tags = ["security", "string-format", "python"]
    version_added = "1.0.0"
    version_changed = "1.0.0"

    _regex = re.compile(r"(?:\.format\s*\(|%\s)")  # .format(   ou   % ...

    # salt-lint appelle match(file, line) pour chaque ligne
    def match(self, file, line: str) -> bool | str:  # <- bonne signature
        # ne scanner que les fichiers Python
        if not str(file["path"]).endswith(".py"):
            return False

        if self._regex.search(line):
            return self.short      # salt-lint signalera cette ligne
        return False
