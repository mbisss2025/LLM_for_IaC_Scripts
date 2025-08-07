from __future__ import annotations
from ansiblelint.rules import AnsibleLintRule


class ReDoSDetector(AnsibleLintRule):
    id = 'SECURITY014'
    shortdesc = 'ReDoS vulnerability detected'
    description = 'Regex pattern concatenation with user input may cause ReDoS'
    severity = 'HIGH'
    tags = ['security', 'python', 'redos']
    version_added = '1.0.0'

    def match(self, line: str) -> bool | str:
        line = line.strip()
        if not line or line.startswith('#'):
            return False
            
        # Check for regex function with string concatenation
        if 're.findall(' in line and '+' in line:
            return f"ReDoS risk: regex concatenation with user input - {line}"
            
        return False