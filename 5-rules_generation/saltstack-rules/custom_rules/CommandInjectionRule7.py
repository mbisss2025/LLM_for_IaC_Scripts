from __future__ import annotations
import re
from saltlint.linter.rule import Rule


class CommandInjectionRule7(Rule):
    # ────────────────────────── Métadonnées
    id = "SECURITY007"
    short = "Security Smell [Command Injection]: run_llvm_mca_tool avec entrée non filtrée"
    description = (
        "Passer directement opts.file_names[i] à run_llvm_mca_tool() peut "
        "permettre d'injecter des arguments malveillants ou de manipuler le "
        "chemin du fichier. Validez ou échappez le nom de fichier."
    )
    severity = "HIGH"
    tags = ["security", "command-injection", "python"]
    version_added = "1.0.0"
    version_changed = "1.0.0"

    # regex : run_llvm_mca_tool(  <qqch> ,  opts.file_names[...] )
    _rgx = re.compile(
        r"run_llvm_mca_tool\([^,]+,\s*opts\.file_names\[[^\]]+\]",
        re.IGNORECASE,
    )

    # salt-lint appelle match(file, line)
    def match(self, file, line: str):  # noqa: D401
        # ne scanner que les helpers Python (*.py)
        if not str(file["path"]).endswith(".py"):
            return False

        return self.short if self._rgx.search(line) else False
