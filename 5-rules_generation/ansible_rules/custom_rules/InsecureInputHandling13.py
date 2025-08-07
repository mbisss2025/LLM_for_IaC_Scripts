from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule

class ReDoSPatternRule13(AnsibleLintRule):
    id = 'SECURITY013'
    shortdesc = "Regular Expression Denial of Service (ReDoS) pattern detected"
    description = "This pattern can lead to ReDoS vulnerabilities due to inefficient regex usage."
    severity = "HIGH"
    tags = {"security", "python"}
    version_added = "1.0.0"

    _pattern = re.compile(r"get_pack_metadata\(")

    def match(self, line: str) -> bool | str:
        line_stripped = line.strip()
        if line_stripped.startswith('#'):
            return False
        if self._pattern.search(line):
            return self.shortdesc
        return False