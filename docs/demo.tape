# RedactGate demo tape — rendered by `vhs docs/demo.tape` (CI: .github/workflows/demo.yml)
# Scripts the 10-minute happy path: scan a leaky file, then mask it on egress.
# Output slot matches the README ## Demo image (assets/demo.gif).

Output assets/demo.gif

Set Shell      "bash"
Set FontSize   18
Set Width      1180
Set Height     680
Set Padding    24
Set Theme      "Dracula"
Set TypingSpeed 45ms

# --- install (shown for context; the binary is already on PATH for the render) -
Type "# 1) install — one command, no config:  pip install redactgate"
Enter
Sleep 1200ms

# --- scan: list every checksum-validated CN-PII hit ---------------------------
Type "# 2) scan a source file that mixes business logic with planted PII"
Enter
Sleep 600ms
Type "redactgate scan examples/demo-repo/leaky.py"
Enter
Sleep 3s

# --- proxy --stdin: mask the egress, append an audit entry --------------------
Type "# 3) mask it before egress — note 110101199003078515 -> 1101**********8515"
Enter
Sleep 600ms
Type "redactgate proxy --stdin < examples/demo-repo/leaky.py | grep id_card"
Enter
Sleep 3s

# --- report: the compliance-self-check summary --------------------------------
Type "# 4) the audit log proves what left the machine (and what didn't)"
Enter
Sleep 600ms
Type "redactgate report"
Enter
Sleep 3s

Type "# business logic reached the model untouched; every 身份证/手机号 was masked."
Enter
Sleep 2.5s
