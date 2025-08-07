from __future__ import annotations
from ansiblelint.rules import AnsibleLintRule


class HardcodedSecretsRule(AnsibleLintRule):
    """Detect hardcoded sensitive credentials in Python code."""
    
    id = 'SECURITY027'
    shortdesc = 'Hardcoded secret detected'
    description = 'Found potentially sensitive credentials hardcoded in source'
    severity = 'HIGH'
    tags = ['security', 'secret']
    version_added = '1.0.0'

    # Common secret indicators
    _secret_indicators = [
        'BEGIN RSA PRIVATE KEY',
        'BEGIN PRIVATE KEY',
        'BEGIN EC PRIVATE KEY',
        'BEGIN OPENSSH PRIVATE KEY',
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'AKIA[0-9A-Z]{16}',  # AWS access key
        'secret_',
        '_token',
        '_password',
        '_key',
        '_secret'
    ]

    def match(self, line: str) -> bool | str:
        line = line.strip()
        
        # Skip empty/commented lines
        if not line or line.startswith('#'):
            return False
            
        # Check for any secret indicators
        for indicator in self._secret_indicators:
            if indicator in line:
                return f"Hardcoded secret detected: {line[:100] + ('...' if len(line) > 100 else '')}"
                
        return False