# DarkShell Demo — Why You Should Care

Output demos/darkshell-overview.gif

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

# Build (hidden)
Hide
Type "cd /Users/jmagady/Dev/DarkShell && alias darkshell='./target/debug/darkshell'"
Enter
Sleep 1s
Show

# --- INTRO ---
Type "# DarkShell: Enhanced sandbox runtime for AI agents"
Enter
Type "# Fork of NVIDIA OpenShell — same security, better DX"
Enter
Sleep 2s

# --- OPENSHELL FOUNDATION ---
Type ""
Enter
Type "# All upstream OpenShell commands work identically:"
Enter
Sleep 1s

Type "darkshell --help"
Enter
Sleep 2s

Type "darkshell sandbox create --help 2>&1 | head -20"
Enter
Sleep 2s

# --- PROBLEM 1: TRANSFER ---
Type ""
Enter
Type "# PROBLEM: OpenShell re-uploads your entire workspace every time"
Enter
Type "# FIX: rsync delta — only changed files transfer"
Enter
Sleep 1s
Type "darkshell sandbox upload --help 2>&1 | head -20"
Enter
Sleep 2s

# --- PROBLEM 2: EXEC ---
Type ""
Enter
Type "# PROBLEM: Every command requires a new SSH session (200-500ms)"
Enter
Type "# FIX: exec with SSH ControlMaster — < 20ms after first call"
Enter
Sleep 1s
Type "darkshell sandbox exec --help 2>&1 | head -15"
Enter
Sleep 2s

# --- PROBLEM 3: MCP ---
Type ""
Enter
Type "# PROBLEM: Connecting MCP servers to sandboxes = 5 manual steps"
Enter
Type "# FIX: One command — bridge daemon, port forward, credentials"
Enter
Sleep 1s
Type "darkshell mcp --help"
Enter
Sleep 2s
Type "darkshell mcp add --help 2>&1 | head -20"
Enter
Sleep 2s

# --- PROBLEM 4: SETUP ---
Type ""
Enter
Type "# PROBLEM: Sandbox setup = 5+ commands for image+policy+creds+MCP+ports"
Enter
Type "# FIX: One YAML blueprint, one command"
Enter
Sleep 1s
Type "cat demos/example-blueprint.yaml"
Enter
Sleep 3s

# --- PROBLEM 5: VISIBILITY ---
Type ""
Enter
Type "# PROBLEM: No idea what your AI agent is doing in the sandbox"
Enter
Type "# FIX: Real-time event streaming with filtering"
Enter
Sleep 1s
Type "darkshell sandbox watch --help 2>&1 | head -15"
Enter
Sleep 2s

# --- DOWNLOAD FILTERING ---
Type ""
Enter
Type "# BONUS: Download only what you need"
Enter
Sleep 1s
Type "darkshell sandbox download --help 2>&1 | head -20"
Enter
Sleep 2s

# --- CLOSING ---
Type ""
Enter
Type "# Same kernel-enforced security as OpenShell:"
Enter
Type "#   Landlock + seccomp + network namespaces + OPA policy"
Enter
Type "# Zero security trade-offs. Just better DX."
Enter
Type "#"
Enter
Type "# github.com/BOHICA-LABS/darkshell"
Enter
Sleep 3s
