from __future__ import annotations
import re
from saltlint.linter.rule import Rule

class SSRFInsecureInputHandlingRule18(Rule):
    id = 'SECURITY018'
    shortdesc = "Potential SSRF vulnerability detected"
    description = "Server-Side Request Forgery (SSRF) vulnerability may exist due to insecure input handling."
    severity = "HIGH"
    tags = ["security", "ssrf", "input_handling"]
    version_added = "1.0.0"
    _pattern = re.compile(r"requests\.get\(.+\.text")

    def match(self, file, line: str) -> bool | str:
        if line.lstrip().startswith("#"):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False

# Alias pour le chargement par Salt-Lint
ssrf_insecure_input_handling_rule18 = SSRFInsecureInputHandlingRule18