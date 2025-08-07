from __future__ import annotations
import re
from ansiblelint.rules import AnsibleLintRule


class PathTraversalDetectionRule(AnsibleLintRule):
    """Detect path traversal vulnerabilities in file operations."""
    
    id = 'SECURITY029'
    shortdesc = 'Path traversal vulnerability detected'
    description = 'File operations using unvalidated paths may allow directory traversal attacks'
    severity = 'HIGH'
    tags = ['security', 'filesystem']
    version_added = '1.0.0'

    # Match file open operations with path variables
    _file_open_pattern = re.compile(
        r'(?:with\s+)?open\s*\(([^)]+)'
    )

    def match(self, line: str) -> bool | str:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return False

        # Check for file open operations
        open_match = self._file_open_pattern.search(line)
        if not open_match:
            return False

        # Get the path argument
        path_arg = open_match.group(1).split(',')[0].strip()
        
        # Check if path is a variable (not a string literal)
        if not (path_arg.startswith(('"', "'", "r'", 'r"')) and not path_arg.startswith(('os.path.join(', 'os.path.abspath('))):
            return f"Potential path traversal - unvalidated path used: {line}"

        return False