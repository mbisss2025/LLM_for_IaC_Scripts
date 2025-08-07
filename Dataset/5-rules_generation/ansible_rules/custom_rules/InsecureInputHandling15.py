from __future__ import annotations
from ansiblelint.rules import AnsibleLintRule


class JinjaAutoEscapeRule(AnsibleLintRule):
    id = 'SECURITY015'
    shortdesc = "Jinja2 template without auto-escape detected"
    description = "Jinja2.Template() without autoescape=True can lead to XSS vulnerabilities"
    severity = "HIGH"
    tags = ["security", "jinja2", "xss"]
    version_added = "1.0.0"

    def match(self, line: str) -> bool | str:
        stripped_line = line.strip()
        
        # Check for jinja2.Template without autoescape=True
        if 'jinja2.Template(' in stripped_line:
            if 'autoescape=True' not in stripped_line:
                return "Jinja2 template created without autoescape=True, potential XSS vulnerability"
        
        return False