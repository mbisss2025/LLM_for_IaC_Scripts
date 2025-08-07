# custom_rules/path_traversal_join.py
from __future__ import annotations
import re
from saltlint.linter.rule import Rule


class PathTraversalRule21(Rule):
    id = "SECURITY021"
    short = "Security Smell [Path Traversal] : fileRename / replaceInFileRegex"
    description = (
        "fileRename() et replaceInFileRegex() déplacent ou ré-écrivent des "
        "fichiers selon un chemin construit dynamiquement ; sans validation "
        "une traversée de répertoires est possible."
    )
    severity = "HIGH"
    tags = ["security", "path-traversal", "python"]
    version_added = "1.0.0"
    version_changed = "1.0.0"

    # Détecte fileRename(…  ou  replaceInFileRegex(
    _rx = re.compile(r"\b(?:fileRename|replaceInFileRegex)\s*\(")

    # salt-lint appelle match(file, line) pour chaque ligne
    def match(self, file, line: str):  # noqa: D401
        # ne scanner que les fichiers Python
        if not str(file["path"]).endswith(".py"):
            return False
        return self.short if self._rx.search(line) else False
