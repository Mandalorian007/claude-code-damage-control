# Claude Code Damage Control

A single-file safety hook for Claude Code that blocks dangerous commands and protects sensitive files.

Inspired by [disler/claude-code-damage-control](https://github.com/disler/claude-code-damage-control), simplified into one standalone Python script with no dependencies.

## What It Does

Intercepts Claude Code's Bash, Edit, and Write tools before execution:

- **Exit 0**: Allow operation
- **Exit 2**: Block operation (with explanation)
- **JSON output**: Request user confirmation

### Protections

| Category | Examples |
|----------|----------|
| **Blocked Commands** | `rm -rf`, `git reset --hard`, `git push --force`, `chmod 777`, `terraform destroy`, `DROP TABLE`, AWS/GCP destructive ops |
| **Zero Access Paths** | `.env*`, `~/.ssh/*`, `~/.aws/*`, `*.pem`, `*.key`, `*.tfstate`, `credentials.json` |
| **Read-Only Paths** | `/etc/*`, `/usr/*`, `package-lock.json`, `node_modules/`, `dist/`, `build/` |
| **No-Delete Paths** | `.git/*`, `README.md`, `Dockerfile`, `.claude/*`, `LICENSE` |

## Install

### 1. Copy the script

```bash
cp damage-control.py ~/.claude/damage-control.py
chmod +x ~/.claude/damage-control.py
```

### 2. Configure hooks

Add to `~/.claude/settings.json` (create if it doesn't exist):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/damage-control.py --tool=bash",
            "timeout": 5000
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/damage-control.py --tool=edit",
            "timeout": 5000
          }
        ]
      },
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/damage-control.py --tool=write",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
```

### 3. Restart Claude Code

The hooks take effect on the next session.

## One-Liner Install

```bash
curl -fsSL https://raw.githubusercontent.com/Mandalorian007/claude-code-damage-control/main/install.sh | bash
```

## Verify Installation

```bash
# Show help
~/.claude/damage-control.py --help

# Show all configured patterns
~/.claude/damage-control.py --show-config
```

## Customization

Edit the Python variables at the top of `damage-control.py`:

- `BLOCKED_BASH_PATTERNS` - Commands that are always blocked
- `ASK_BASH_PATTERNS` - Commands that trigger confirmation
- `ZERO_ACCESS_PATHS` - No access at all (glob patterns)
- `READ_ONLY_PATHS` - Can read, can't modify
- `NO_DELETE_PATHS` - Can read/write, can't delete

## How It Works

```
Claude Code Tool Call
        │
        ▼
   PreToolUse Hook
        │
        ▼
 damage-control.py
        │
        ├── Bash? → Check command patterns → Check path access
        ├── Edit? → Check path protection (write)
        └── Write? → Check path protection (write)
        │
        ▼
   Exit 0 (allow) / Exit 2 (block) / JSON (ask)
```

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## Credits

- Concept from [disler/claude-code-damage-control](https://github.com/disler/claude-code-damage-control)
- Simplified single-file implementation
