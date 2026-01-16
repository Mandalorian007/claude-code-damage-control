#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Claude Code Damage Control - Unified Hook Script

Usage:
  damage-control.py --tool=bash    # For Bash tool hook
  damage-control.py --tool=edit    # For Edit tool hook
  damage-control.py --tool=write   # For Write tool hook

Installation:
  1. Copy this file to ~/.claude/damage-control.py
  2. Make executable: chmod +x ~/.claude/damage-control.py
  3. Add hooks to ~/.claude/settings.json (see SETTINGS_TEMPLATE below)

Exit Codes:
  0 = Allow operation
  2 = Block operation (message sent to stderr)
"""

import sys
import json
import re
import os
import fnmatch
from pathlib import Path

# =============================================================================
# CONFIGURATION - Edit these sections to customize protection
# =============================================================================

# Bash commands that are ALWAYS blocked (regex patterns)
BLOCKED_BASH_PATTERNS = [
    # Destructive file operations
    (r"\brm\s+.*-[rRf]", "rm with recursive/force flags"),
    (r"\brm\s+-[^-]*r", "rm with recursive flag"),
    (r"\brmdir\s+--ignore-fail", "rmdir ignoring failures"),
    (r"\bsudo\s+rm\s+-rf\s+/", "sudo rm -rf on root paths"),

    # Dangerous permission changes
    (r"\bchmod\s+777\b", "chmod 777 (world-writable)"),
    (r"\bchmod\s+-R\s+777\b", "recursive chmod 777"),
    (r"\bchown\s+-R\s+root", "recursive chown to root"),

    # Git destructive operations
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard (use --soft or stash)"),
    (r"\bgit\s+clean\s+.*-[fd]", "git clean with force/directory flags"),
    (r"\bgit\s+push\s+.*--force\b(?!-with-lease)", "git push --force (use --force-with-lease)"),
    (r"\bgit\s+stash\s+clear\b", "git stash clear"),
    (r"\bgit\s+reflog\s+expire\b", "git reflog expire"),
    (r"\bgit\s+filter-branch\b", "git filter-branch"),

    # Cloud/infrastructure destruction - AWS
    (r"\baws\s+s3\s+rm\s+.*--recursive\b", "AWS S3 recursive delete"),
    (r"\baws\s+s3\s+rb\s+.*--force\b", "AWS S3 bucket force delete"),
    (r"\baws\s+ec2\s+terminate-instances\b", "AWS EC2 terminate"),
    (r"\baws\s+rds\s+delete-db-instance\b", "AWS RDS delete"),
    (r"\baws\s+dynamodb\s+delete-table\b", "AWS DynamoDB delete table"),

    # Cloud/infrastructure destruction - GCP
    (r"\bgcloud\s+projects\s+delete\b", "GCP project delete"),
    (r"\bgcloud\s+compute\s+instances\s+delete\b", "GCP instance delete"),
    (r"\bgcloud\s+container\s+clusters\s+delete\b", "GKE cluster delete"),

    # Cloud/infrastructure destruction - Firebase/Vercel/Netlify
    (r"\bfirebase\s+projects:delete\b", "Firebase project delete"),
    (r"\bfirebase\s+database:remove\b", "Firebase database remove"),
    (r"\bvercel\s+remove\b", "Vercel project remove"),
    (r"\bnetlify\s+sites:delete\b", "Netlify site delete"),

    # Container/orchestration destruction
    (r"\bdocker\s+system\s+prune\s+-a\b", "docker system prune -a"),
    (r"\bdocker\s+volume\s+prune\b", "docker volume prune"),
    (r"\bkubectl\s+delete\s+namespace\b", "kubectl delete namespace"),
    (r"\bkubectl\s+delete\s+.*--all\b", "kubectl delete --all"),

    # Infrastructure as code destruction
    (r"\bterraform\s+destroy\b", "terraform destroy"),
    (r"\bpulumi\s+destroy\b", "pulumi destroy"),
    (r"\bserverless\s+remove\b", "serverless remove"),

    # Database destruction
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "SQL DROP statement"),
    (r"\bTRUNCATE\s+TABLE\b", "SQL TRUNCATE"),
    (r"\bDELETE\s+FROM\s+\w+\s*;", "SQL DELETE without WHERE"),
    (r"\bDELETE\s+FROM\s+\w+\s*$", "SQL DELETE without WHERE"),
    (r"\bFLUSHALL\b", "Redis FLUSHALL"),
    (r"\bFLUSHDB\b", "Redis FLUSHDB"),
    (r"\.dropDatabase\s*\(", "MongoDB dropDatabase"),

    # System destruction
    (r"\bmkfs\b", "filesystem format"),
    (r"\bdd\s+if=.*of=/dev/", "dd to device"),
    (r">\s*/dev/sd[a-z]", "redirect to block device"),
]

# Bash commands that require user confirmation (regex patterns)
# These output JSON to trigger the ask dialog instead of blocking
ASK_BASH_PATTERNS = [
    (r"\bgit\s+checkout\s+--\s+\.", "git checkout -- . (discards uncommitted changes)"),
    (r"\bgit\s+stash\s+drop\b", "git stash drop"),
    (r"\bgit\s+branch\s+-D\b", "git branch -D (force delete)"),
    (r"\bDELETE\s+FROM\s+\w+\s+WHERE\s+id\s*=", "SQL DELETE with specific ID"),
]

# Paths with ZERO access (no read, write, edit, or delete)
# Supports ~ expansion and glob patterns (*, **, ?)
ZERO_ACCESS_PATHS = [
    # Environment/secrets
    ".env",
    ".env.*",
    "*.env",
    ".env.local",
    ".env.production",

    # SSH/GPG/credentials
    "~/.ssh/*",
    "~/.gnupg/*",
    "~/.aws/*",
    "~/.azure/*",
    "~/.config/gcloud/*",
    "~/.kube/*",
    "**/kubeconfig",
    "**/kubeconfig.yaml",
    "~/.docker/config.json",

    # Certificates and keys
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/id_rsa",
    "**/id_ed25519",
    "**/id_ecdsa",

    # Infrastructure state (contains secrets)
    "**/*.tfstate",
    "**/*.tfstate.backup",
    "**/.terraform/*",

    # Platform tokens
    "~/.vercel/*",
    "~/.netlify/*",

    # Auth files
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.git-credentials",
    "**/credentials.json",
    "**/service-account*.json",
]

# Paths that are READ-ONLY (can read, but no write/edit/delete)
READ_ONLY_PATHS = [
    # System directories
    "/etc/*",
    "/usr/*",
    "/bin/*",
    "/sbin/*",
    "/boot/*",
    "/System/*",

    # Lock files (should be managed by package managers)
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/Cargo.lock",
    "**/Gemfile.lock",
    "**/poetry.lock",
    "**/composer.lock",
    "**/go.sum",

    # Build artifacts (regenerated, don't edit manually)
    "**/dist/*",
    "**/build/*",
    "**/node_modules/*",
    "**/.next/*",
    "**/target/*",
    "**/__pycache__/*",
    "**/*.pyc",
]

# Paths protected from DELETION only (can read, write, edit)
NO_DELETE_PATHS = [
    # Git
    "**/.git/*",
    "**/.github/*",
    "**/.gitignore",
    "**/.gitattributes",

    # Project documentation
    "**/README.md",
    "**/README.rst",
    "**/LICENSE*",
    "**/CONTRIBUTING.md",
    "**/CHANGELOG.md",
    "**/CODE_OF_CONDUCT.md",

    # CI/CD
    "**/.gitlab-ci.yml",
    "**/Jenkinsfile",
    "**/.travis.yml",
    "**/.circleci/*",

    # Containerization
    "**/Dockerfile",
    "**/docker-compose.yml",
    "**/docker-compose.yaml",
    "**/.dockerignore",

    # Claude configuration
    "**/.claude/*",
    "**/CLAUDE.md",
]

# Settings template for ~/.claude/settings.json
SETTINGS_TEMPLATE = """
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "command": "~/.claude/damage-control.py --tool=bash",
            "timeout": 5000
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "command": "~/.claude/damage-control.py --tool=edit",
            "timeout": 5000
          }
        ]
      },
      {
        "matcher": "Write",
        "hooks": [
          {
            "command": "~/.claude/damage-control.py --tool=write",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
"""

# =============================================================================
# IMPLEMENTATION - Generally no need to edit below this line
# =============================================================================

def expand_path(pattern: str) -> str:
    """Expand ~ and environment variables in path patterns."""
    return os.path.expanduser(os.path.expandvars(pattern))


def is_glob_pattern(pattern: str) -> bool:
    """Check if pattern contains glob wildcards."""
    return any(c in pattern for c in "*?[")


def match_path(filepath: str, pattern: str) -> bool:
    """Check if filepath matches a pattern (supports globs and prefix matching)."""
    expanded_pattern = expand_path(pattern)
    normalized_path = os.path.normpath(os.path.expanduser(filepath))
    normalized_pattern = os.path.normpath(expanded_pattern)

    # Try exact match first
    if normalized_path.lower() == normalized_pattern.lower():
        return True

    # Try glob matching
    if is_glob_pattern(pattern):
        if fnmatch.fnmatch(normalized_path.lower(), normalized_pattern.lower()):
            return True
        # Also try with ** for recursive matching
        if "**" in pattern:
            parts = normalized_pattern.split("**")
            if len(parts) == 2:
                prefix, suffix = parts
                if normalized_path.lower().startswith(prefix.rstrip("/\\").lower()):
                    if suffix:
                        if normalized_path.lower().endswith(suffix.lstrip("/\\").lower()):
                            return True
                    else:
                        return True

    # Try prefix matching for directory patterns
    if normalized_pattern.endswith(("/*", "\\*")):
        dir_pattern = normalized_pattern[:-2]
        if normalized_path.lower().startswith(dir_pattern.lower()):
            return True

    # Check if path is under the pattern directory
    if normalized_path.lower().startswith(normalized_pattern.lower() + os.sep):
        return True

    return False


def check_path_protection(filepath: str, operation: str) -> tuple[bool, str]:
    """
    Check if a path is protected for the given operation.

    Args:
        filepath: The file path to check
        operation: One of 'read', 'write', 'edit', 'delete'

    Returns:
        (is_blocked, reason) tuple
    """
    # Check zero access paths (blocks everything)
    for pattern in ZERO_ACCESS_PATHS:
        if match_path(filepath, pattern):
            return True, f"Path matches zero-access pattern: {pattern}"

    # Check read-only paths (blocks write, edit, delete)
    if operation in ("write", "edit", "delete"):
        for pattern in READ_ONLY_PATHS:
            if match_path(filepath, pattern):
                return True, f"Path is read-only: {pattern}"

    # Check no-delete paths (blocks only delete)
    if operation == "delete":
        for pattern in NO_DELETE_PATHS:
            if match_path(filepath, pattern):
                return True, f"Path is protected from deletion: {pattern}"

    return False, ""


def check_bash_command(command: str) -> tuple[str, str]:
    """
    Check a bash command against patterns.

    Returns:
        (action, reason) where action is 'allow', 'block', or 'ask'
    """
    # Check blocked patterns first
    for pattern, reason in BLOCKED_BASH_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return "block", reason

    # Check ask patterns
    for pattern, reason in ASK_BASH_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return "ask", reason

    # Check if command accesses protected paths
    # Extract paths from common command patterns
    path_patterns = [
        r'\bcat\s+([^\s|>&;]+)',
        r'\bless\s+([^\s|>&;]+)',
        r'\bhead\s+(?:-\d+\s+)?([^\s|>&;]+)',
        r'\btail\s+(?:-\d+\s+)?([^\s|>&;]+)',
        r'\brm\s+(?:-[^\s]+\s+)*([^\s]+)',
        r'\bcp\s+(?:-[^\s]+\s+)*([^\s]+)',
        r'\bmv\s+(?:-[^\s]+\s+)*([^\s]+)',
        r'\bchmod\s+\d+\s+([^\s]+)',
        r'\bchown\s+[^\s]+\s+([^\s]+)',
        r'>\s*([^\s;&|]+)',
        r'>>\s*([^\s;&|]+)',
    ]

    for path_pattern in path_patterns:
        matches = re.findall(path_pattern, command)
        for match in matches:
            # Determine operation type from command
            if re.search(r'\brm\b', command):
                op = "delete"
            elif re.search(r'\b(cat|less|head|tail|grep)\b', command):
                op = "read"
            elif re.search(r'>>?\s*' + re.escape(match), command):
                op = "write"
            else:
                op = "write"  # default to write for safety

            blocked, reason = check_path_protection(match, op)
            if blocked:
                return "block", f"Command accesses protected path: {reason}"

    return "allow", ""


def handle_bash(tool_input: dict) -> int:
    """Handle Bash tool hook."""
    command = tool_input.get("command", "")

    action, reason = check_bash_command(command)

    if action == "block":
        print(f"BLOCKED: {reason}", file=sys.stderr)
        print(f"Command: {command[:100]}{'...' if len(command) > 100 else ''}", file=sys.stderr)
        return 2

    if action == "ask":
        # Output JSON to trigger confirmation dialog
        response = {
            "decision": "ask",
            "message": f"This command may be destructive: {reason}\n\nCommand: {command[:200]}"
        }
        print(json.dumps(response))
        return 0

    return 0


def handle_edit(tool_input: dict) -> int:
    """Handle Edit tool hook."""
    filepath = tool_input.get("file_path", "")

    # Edit is always a 'write' operation
    blocked, reason = check_path_protection(filepath, "edit")

    if blocked:
        print(f"BLOCKED: Cannot edit protected file", file=sys.stderr)
        print(f"Reason: {reason}", file=sys.stderr)
        print(f"Path: {filepath}", file=sys.stderr)
        return 2

    return 0


def handle_write(tool_input: dict) -> int:
    """Handle Write tool hook."""
    filepath = tool_input.get("file_path", "")

    blocked, reason = check_path_protection(filepath, "write")

    if blocked:
        print(f"BLOCKED: Cannot write to protected path", file=sys.stderr)
        print(f"Reason: {reason}", file=sys.stderr)
        print(f"Path: {filepath}", file=sys.stderr)
        return 2

    return 0


def main():
    # Parse --tool argument
    tool = None
    for arg in sys.argv[1:]:
        if arg.startswith("--tool="):
            tool = arg.split("=", 1)[1].lower()
        elif arg == "--help":
            print(__doc__)
            print("\nSettings template for ~/.claude/settings.json:")
            print(SETTINGS_TEMPLATE)
            return 0
        elif arg == "--show-config":
            print("=== BLOCKED BASH PATTERNS ===")
            for pattern, reason in BLOCKED_BASH_PATTERNS:
                print(f"  {reason}: {pattern}")
            print("\n=== ASK BASH PATTERNS ===")
            for pattern, reason in ASK_BASH_PATTERNS:
                print(f"  {reason}: {pattern}")
            print("\n=== ZERO ACCESS PATHS ===")
            for p in ZERO_ACCESS_PATHS:
                print(f"  {p}")
            print("\n=== READ-ONLY PATHS ===")
            for p in READ_ONLY_PATHS:
                print(f"  {p}")
            print("\n=== NO-DELETE PATHS ===")
            for p in NO_DELETE_PATHS:
                print(f"  {p}")
            return 0

    if not tool:
        print("Error: --tool argument required (bash, edit, or write)", file=sys.stderr)
        print("Usage: damage-control.py --tool=bash", file=sys.stderr)
        return 2

    if tool not in ("bash", "edit", "write"):
        print(f"Error: Unknown tool '{tool}'. Must be bash, edit, or write.", file=sys.stderr)
        return 2

    # Read tool input from stdin (JSON from Claude Code)
    try:
        stdin_data = sys.stdin.read()
        if not stdin_data.strip():
            # No input provided - this might be a test run
            return 0

        hook_input = json.loads(stdin_data)
        tool_input = hook_input.get("tool_input", {})
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON input: {e}", file=sys.stderr)
        return 2

    # Route to appropriate handler
    handlers = {
        "bash": handle_bash,
        "edit": handle_edit,
        "write": handle_write,
    }

    return handlers[tool](tool_input)


if __name__ == "__main__":
    sys.exit(main())
