from __future__ import annotations
from ansiblelint.rules import AnsibleLintRule


class PathTraversalRule(AnsibleLintRule):
    id = 'SECURITY030'
    shortdesc = 'Potential path traversal vulnerability'
    description = 'File operations using unvalidated path components may allow directory traversal'
    severity = 'HIGH'
    tags = ['security', 'filesystem']
    version_added = '1.0.0'

    def match(self, line: str) -> bool | str:
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            return False
            
        # Check for file operations with dynamic path components
        if ('os.path.join(' in line and 
            any(op in line for op in ['shutil.', 'open(']) and
            any(var in line for var in ['to_release', 'from_release'])):
            return f"Potential path traversal with dynamic path component: {line}"
            
        return False