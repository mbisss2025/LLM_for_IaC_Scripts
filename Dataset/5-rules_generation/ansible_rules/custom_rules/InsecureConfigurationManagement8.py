from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule


class InsecureSSLVerificationRule(AnsibleLintRule):
    id = 'SECURITY008'
    shortdesc = "Insecure SSL verification detected"
    description = "Potential insecure SSL configuration identified. Requests should verify SSL certificates (verify=True)."
    severity = "HIGH"
    tags = {"security", "python", "ssl"}
    version_added = "1.0.0"

    def match(self, line: str) -> bool | str:
        # Match verify=False, verify=0, or verify=variable_that_might_be_false
        insecure_pattern = re.compile(r'verify\s*=\s*(False|0|\w+\s*(?=\W|$))')
        match = insecure_pattern.search(line)
        if match:
            # Check if it's explicitly False/0 or a variable (might be False)
            value = match.group(1)
            if value in ('False', '0') or (value.isidentifier() and not value == 'True'):
                return f"Insecure SSL verification found: {match.group(0)}"
        return False