# DarkShell Live Demo — Real Sandbox with AI Agents

Output demos/darkshell-live.gif

Set FontSize 16
Set FontFamily "Menlo"
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set WindowBarSize 40
Set BorderRadius 8
Set Padding 15
Set Framerate 24
Set PlaybackSpeed 1.5
Set TypingSpeed 30ms

# Setup (hidden)
Hide
Type "cd /Users/jmagady/Dev/DarkShell && alias darkshell='./target/debug/darkshell'"
Enter
Sleep 1s
Show

# --- CHECK GATEWAY ---
Type "# Connect to a running DarkShell gateway"
Enter
Sleep 1s
Type "darkshell status"
Enter
Sleep 2s

# --- LIST SANDBOXES ---
Type ""
Enter
Type "# See what sandboxes are running"
Enter
Sleep 1s
Type "darkshell sandbox list"
Enter
Sleep 2s

# --- INSPECT SANDBOX ---
Type ""
Enter
Type "# Inspect the sandbox — policy, isolation, credentials"
Enter
Sleep 1s
Type "darkshell sandbox get dark-factory 2>&1 | head -30"
Enter
Sleep 3s

# --- EXEC INTO SANDBOX ---
Type ""
Enter
Type "# Execute commands directly — no SSH session overhead"
Enter
Sleep 1s
Type "darkshell sandbox exec dark-factory -- whoami"
Enter
Sleep 2s

Type "darkshell sandbox exec dark-factory -- uname -a"
Enter
Sleep 2s

# --- SHOW CLAUDE CODE ---
Type ""
Enter
Type "# Claude Code is running inside the sandbox"
Enter
Sleep 1s
Type "darkshell sandbox exec dark-factory -- claude --version"
Enter
Sleep 2s

# --- SHOW OPENCLAW ---
Type ""
Enter
Type "# OpenClaw agent framework is also available"
Enter
Sleep 1s
Type "darkshell sandbox exec dark-factory -- openclaw --version"
Enter
Sleep 2s

Type "darkshell sandbox exec dark-factory -- openclaw --help 2>&1 | head -10"
Enter
Sleep 3s

# --- UPLOAD FILES ---
Type ""
Enter
Type "# Upload files into the sandbox — instantly"
Enter
Sleep 1s
Type "darkshell sandbox upload dark-factory /tmp/test-upload.txt"
Enter
Sleep 2s

Type "darkshell sandbox exec dark-factory -- cat /sandbox/test-upload.txt"
Enter
Sleep 2s

# --- SHOW PROCESSES ---
Type ""
Enter
Type "# See what's running inside the isolated sandbox"
Enter
Sleep 1s
Type "darkshell sandbox exec dark-factory -- ps aux"
Enter
Sleep 3s

# --- SHOW LOGS ---
Type ""
Enter
Type "# Stream sandbox logs — gateway, proxy, SSH tunnels"
Enter
Sleep 1s
Type "darkshell logs dark-factory --since 5m 2>&1 | tail -10"
Enter
Sleep 3s

# --- SHOW SECURITY ---
Type ""
Enter
Type "# Kernel-enforced isolation is active"
Enter
Sleep 1s
Type "darkshell sandbox exec dark-factory -- cat /proc/self/status 2>&1 | grep -E 'Seccomp|NoNewPrivs'"
Enter
Sleep 2s

# --- SHOW MCP COMMANDS ---
Type ""
Enter
Type "# MCP server management — connect tools to sandboxes"
Enter
Sleep 1s
Type "darkshell mcp add --help 2>&1 | head -15"
Enter
Sleep 3s

# --- SHOW BLUEPRINT ---
Type ""
Enter
Type "# Or define everything in one blueprint file"
Enter
Sleep 1s
Type "cat demos/example-blueprint.yaml"
Enter
Sleep 4s

# --- CLOSING ---
Type ""
Enter
Type "# DarkShell: Real sandboxes. Real agents. Real isolation."
Enter
Type "# github.com/BOHICA-LABS/darkshell"
Enter
Sleep 3s
