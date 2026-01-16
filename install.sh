#!/bin/bash
# Claude Code Damage Control - One-liner installer
set -e

SCRIPT_URL="https://raw.githubusercontent.com/Mandalorian007/claude-code-damage-control/main/damage-control.py"
CLAUDE_DIR="$HOME/.claude"
SCRIPT_PATH="$CLAUDE_DIR/damage-control.py"
SETTINGS_PATH="$CLAUDE_DIR/settings.json"

echo "Installing Claude Code Damage Control..."

# Create .claude directory if needed
mkdir -p "$CLAUDE_DIR"

# Download the script
echo "Downloading damage-control.py..."
curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"
chmod +x "$SCRIPT_PATH"
echo "  Installed: $SCRIPT_PATH"

# Configure settings.json
if [ -f "$SETTINGS_PATH" ]; then
    # Check if hooks already configured
    if grep -q "damage-control.py" "$SETTINGS_PATH" 2>/dev/null; then
        echo "  Hooks already configured in settings.json"
    else
        echo ""
        echo "Add the following to your $SETTINGS_PATH:"
        echo ""
        cat << 'SETTINGS'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "~/.claude/damage-control.py --tool=bash", "timeout": 5000 }]
      },
      {
        "matcher": "Edit",
        "hooks": [{ "type": "command", "command": "~/.claude/damage-control.py --tool=edit", "timeout": 5000 }]
      },
      {
        "matcher": "Write",
        "hooks": [{ "type": "command", "command": "~/.claude/damage-control.py --tool=write", "timeout": 5000 }]
      }
    ]
  }
}
SETTINGS
        echo ""
        echo "(Manual merge required - existing settings.json detected)"
    fi
else
    # Create new settings.json
    cat > "$SETTINGS_PATH" << 'SETTINGS'
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
SETTINGS
    echo "  Created: $SETTINGS_PATH"
fi

echo ""
echo "Done! Restart Claude Code for changes to take effect."
echo ""
echo "Verify with: ~/.claude/damage-control.py --show-config"
