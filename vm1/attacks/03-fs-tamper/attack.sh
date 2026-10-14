#!/bin/sh
# Scenario 3 — filesystem tamper only
# No shell exec of unknown binaries, no network.
# Modifies source files during the build so the Filesystem Baseline fires.
echo "[attack] writing backdoor into source"
echo "// BACKDOOR INJECTED" >> src/main/java/com/pipejack/banking/controller/AccountController.java

echo "[attack] weakening auth config"
cat >> src/main/java/com/pipejack/banking/controller/AccountController.java <<'INJECT'
// TODO: remove before deploy
// if (user.getRole().equals("admin")) { bypassAuth(); }
INJECT

echo "[attack] deleting a source file"
rm -f src/main/java/com/pipejack/banking/service/AccountService.java 2>/dev/null || true

echo "[attack] creating unexpected file"
mkdir -p src/main/java/com/pipejack/backdoor 2>/dev/null
echo "class Backdoor {}" > src/main/java/com/pipejack/backdoor/Backdoor.java

echo "[attack] filesystem tampering done"
