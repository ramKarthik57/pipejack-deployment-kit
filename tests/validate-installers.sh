#!/usr/bin/env bash
# PipeJack Deployment Kit — Installer and Syntax Validator
# Validates Bash syntax, CLI arguments, dry-run execution, PowerShell syntax, and YAML configuration.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================"
echo " PIPEJACK DEPLOYMENT KIT — INSTALLER & SYNTAX VALIDATOR"
echo "============================================================"

FAILURES=0

# 1. Bash Syntax Validation (bash -n on all shell scripts)
echo
echo "[+] 1/5 Checking Bash Syntax with 'bash -n'..."
SYNTAX_FAILURES=0
while IFS= read -r -d '' sh_file; do
    if ! bash -n "$sh_file"; then
        echo "  [-] Syntax error in: $sh_file"
        SYNTAX_FAILURES=$((SYNTAX_FAILURES + 1))
    fi
done < <(find "$ROOT_DIR" -type f -name "*.sh" -print0)

if [ $SYNTAX_FAILURES -eq 0 ]; then
    echo "  [OK] All Bash scripts passed syntax verification without errors."
else
    FAILURES=$((FAILURES + SYNTAX_FAILURES))
fi

# 2. VM1 Installer Argument & Dry-Run Tests
echo
echo "[+] 2/5 Testing VM1 Installer CLI Options..."
if "$ROOT_DIR/vm1/install.sh" --help >/dev/null; then
    echo "  [OK] vm1/install.sh --help succeeded."
else
    echo "  [-] vm1/install.sh --help failed!"
    FAILURES=$((FAILURES + 1))
fi

if "$ROOT_DIR/vm1/install.sh" --dry-run >/dev/null; then
    echo "  [OK] vm1/install.sh --dry-run succeeded."
else
    echo "  [-] vm1/install.sh --dry-run failed!"
    FAILURES=$((FAILURES + 1))
fi

# 3. VM2 Installer Argument & Dry-Run Tests
echo
echo "[+] 3/5 Testing VM2 Installer CLI Options..."
if "$ROOT_DIR/vm2/install.sh" --help >/dev/null; then
    echo "  [OK] vm2/install.sh --help succeeded."
else
    echo "  [-] vm2/install.sh --help failed!"
    FAILURES=$((FAILURES + 1))
fi

if "$ROOT_DIR/vm2/install.sh" --dry-run >/dev/null; then
    echo "  [OK] vm2/install.sh --dry-run succeeded."
else
    echo "  [-] vm2/install.sh --dry-run failed!"
    FAILURES=$((FAILURES + 1))
fi

# 4. PowerShell Syntax & Block Structure Audit
echo
echo "[+] 4/5 Validating Windows PowerShell Scripts..."
PS_FAILURES=0
for ps_file in "$ROOT_DIR"/windows/*.ps1; do
    if [ -f "$ps_file" ]; then
        # Check for param block and matching braces
        python3 -c "
import sys
with open('$ps_file', 'r', encoding='utf-8') as f:
    content = f.read()
if 'param(' not in content and 'param (' not in content:
    print('Missing param block in $ps_file')
    sys.exit(1)
open_curly = content.count('{')
close_curly = content.count('}')
if open_curly != close_curly:
    print(f'Mismatched braces in $ps_file: {open_curly} open vs {close_curly} close')
    sys.exit(1)
" || {
            echo "  [-] PowerShell structure validation failed on: $ps_file"
            PS_FAILURES=$((PS_FAILURES + 1))
        }
        echo "  [OK] $(basename "$ps_file") passed structure audit."
    fi
done

if [ $PS_FAILURES -gt 0 ]; then
    FAILURES=$((FAILURES + PS_FAILURES))
fi

# 5. YAML Configuration & Policy Syntax Validation
echo
echo "[+] 5/5 Validating PipeJack YAML Policies and Netplan Templates..."
YAML_FAILURES=0
YAML_FILES=(
    "vm2/deployment/policies/policy-banking.yaml"
    "vm2/deployment/policies/policy-node.yaml"
    "vm2/deployment/policies/policy-python.yaml"
    "vm2/deployment/policies/policy-spring.yaml"
    "shared/templates/01-netplan-vm1.yaml.example"
    "shared/templates/01-netplan-vm2.yaml.example"
)

for yml_rel in "${YAML_FILES[@]}"; do
    yml_file="$ROOT_DIR/$yml_rel"
    if [ -f "$yml_file" ]; then
        python3 -c "
import yaml, sys
try:
    with open('$yml_file') as f:
        yaml.safe_load(f)
except Exception as e:
    print('YAML error in $yml_file:', e)
    sys.exit(1)
" || {
            echo "  [-] YAML validation failed on: $yml_rel"
            YAML_FAILURES=$((YAML_FAILURES + 1))
        }
        echo "  [OK] $yml_rel parsed successfully."
    else
        echo "  [-] YAML file missing: $yml_rel"
        YAML_FAILURES=$((YAML_FAILURES + 1))
    fi
done

if [ $YAML_FAILURES -eq 0 ]; then
    echo "  [OK] All YAML policies and templates parsed successfully."
else
    FAILURES=$((FAILURES + YAML_FAILURES))
fi

echo
echo "============================================================"
if [ $FAILURES -eq 0 ]; then
    echo " [PASSED] All installer CLI flags, dry-runs, and syntax tests PASSED."
    echo "============================================================"
    exit 0
else
    echo " [FAILED] $FAILURES installer or syntax validation failure(s) detected!"
    echo "============================================================"
    exit 1
fi
