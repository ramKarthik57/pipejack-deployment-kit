#!/usr/bin/env python3
import json
import time
import urllib.request
import urllib.error
import base64
import os
import sys

GECKODRIVER_URL = "http://127.0.0.1:4444"
CONSOLE_URL = "http://192.168.88.133:8090"
ARTIFACTS_DIR = "/home/ubuntu/.gemini/antigravity/brain/b28a1cc4-e27e-43e8-a2cf-417cadf32082"

class BrowserDriver:
    def __init__(self, base_url=GECKODRIVER_URL):
        self.base_url = base_url
        self.session_id = None

    def post(self, endpoint, data=None):
        url = f"{self.base_url}{endpoint}"
        body = json.dumps(data or {}).encode('utf-8')
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def get(self, endpoint):
        url = f"{self.base_url}{endpoint}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def delete(self, endpoint):
        url = f"{self.base_url}{endpoint}"
        req = urllib.request.Request(url, method="DELETE")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def start_session(self):
        caps = {
            "capabilities": {
                "alwaysMatch": {
                    "moz:firefoxOptions": {
                        "args": ["-headless", "--width=1600", "--height=1000"]
                    }
                }
            }
        }
        res = self.post("/session", caps)
        self.session_id = res["value"]["sessionId"]
        print(f"[+] Started Firefox session: {self.session_id}")

    def navigate(self, url):
        self.post(f"/session/{self.session_id}/url", {"url": url})
        time.sleep(1)

    def execute_script(self, script, args=None):
        res = self.post(f"/session/{self.session_id}/execute/sync", {"script": script, "args": args or []})
        return res.get("value")

    def take_screenshot(self, filename):
        res = self.get(f"/session/{self.session_id}/screenshot")
        b64_data = res.get("value")
        if b64_data:
            filepath = os.path.join(ARTIFACTS_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(base64.b64decode(b64_data))
            print(f"[+] Saved screenshot to: {filepath}")
            return filepath
        return None

    def close(self):
        if self.session_id:
            try:
                self.delete(f"/session/{self.session_id}")
                print("[+] Closed Firefox session")
            except Exception as e:
                print(f"[-] Error closing session: {e}")

def main():
    driver = BrowserDriver()
    try:
        driver.start_session()
        print(f"[+] Navigating to {CONSOLE_URL}...")
        driver.navigate(CONSOLE_URL)
        time.sleep(2)

        # 1. Switch to App Playground Tab
        print("[+] Switching to App Playground tab...")
        driver.execute_script("switchWorkspaceTab('playground');")
        time.sleep(1)

        # ---------------------------------------------
        # TEST 1: Banking App View
        # ---------------------------------------------
        print("\n--- Verifying Banking Application ---")
        driver.execute_script("window.setUnlockedApp('banking'); return 'done';")
        time.sleep(1)

        # Verify .acid-guarantees-panel is completely removed
        acid_count = driver.execute_script("return document.querySelectorAll('.acid-guarantees-panel').length;")
        print(f"[+] ACID Guarantees panel count (Must be 0): {acid_count}")
        assert acid_count == 0, "Error: ACID panel still found in banking view!"

        # Verify microservice badges
        banking_badges = driver.execute_script("return Array.from(document.querySelectorAll('#pg-subview-banking .pg-ms-badge')).map(e => e.textContent.trim());")
        print(f"[+] Banking Microservices in Playground: {banking_badges}")
        assert len(banking_badges) >= 3, "Banking should show at least 3 microservices"

        # Check initial balance
        initial_bal = driver.execute_script("return document.getElementById('acc-bal-1001').textContent.trim();")
        print(f"[+] Initial Alice Vance Balance: {initial_bal}")
        assert "$" in initial_bal, "Balance text missing dollar amount"

        # Execute ACID Fund Transfer
        driver.execute_script("executePlaygroundTransfer(); return 'done';")
        time.sleep(1.5)

        updated_bal = driver.execute_script("return document.getElementById('acc-bal-1001').textContent.trim();")
        feedback = driver.execute_script("return document.getElementById('transfer-feedback').textContent.trim();")
        print(f"[+] Transfer executed! Updated Balance: {updated_bal} | Feedback: {feedback[:60]}...")
        assert updated_bal != initial_bal or "SUCCESS" in feedback.upper()

        driver.take_screenshot("playground_banking_verified.png")

        # ---------------------------------------------
        # TEST 2: Calculator App (Circle Area fix)
        # ---------------------------------------------
        print("\n--- Verifying Calculator Application ---")
        driver.execute_script("window.setUnlockedApp('calc'); return 'done';")
        time.sleep(1)

        # Trigger Circle Area evaluation
        driver.execute_script("setCalcExpr('pi * 15^2'); return 'done';")
        time.sleep(1)

        calc_res = driver.execute_script("return document.getElementById('calc-res-val').textContent.trim();")
        print(f"[+] Calculator 'Circle Area' result: {calc_res}")
        assert "706.85" in calc_res, f"Unexpected calculator result: {calc_res}"

        driver.take_screenshot("playground_calc_verified.png")

        # ---------------------------------------------
        # TEST 3: Node.js Payment Gateway Simulator
        # ---------------------------------------------
        print("\n--- Verifying Node.js Payment Gateway Simulator ---")
        driver.execute_script("window.setUnlockedApp('node'); return 'done';")
        time.sleep(1)

        # Fill test card
        driver.execute_script("fillTestCard('visa'); return 'done';")
        time.sleep(0.5)

        # Authorize payment
        driver.execute_script("executePaymentCheckout(); return 'done';")
        time.sleep(1.5)

        pay_pill = driver.execute_script("return document.getElementById('pay-status-pill') ? document.getElementById('pay-status-pill').textContent.trim() : '';")
        pay_id = driver.execute_script("return document.getElementById('pay-res-id') ? document.getElementById('pay-res-id').textContent.trim() : '';")
        print(f"[+] Payment status: {pay_pill} | Charge ID: {pay_id}")
        assert "200" in pay_pill or "APPROVED" in pay_pill.upper() or "ch_" in pay_id

        # Dispatch settlement webhook
        driver.execute_script("dispatchPaymentWebhook('charge.captured'); return 'done';")
        time.sleep(1)
        wh_status = driver.execute_script("return document.getElementById('pay-res-webhook') ? document.getElementById('pay-res-webhook').textContent.trim() : '';")
        print(f"[+] Webhook status: {wh_status}")

        driver.take_screenshot("playground_payment_verified.png")

        # ---------------------------------------------
        # TEST 4: Python AI Fraud Detection Studio
        # ---------------------------------------------
        print("\n--- Verifying Python AI Fraud Studio ---")
        driver.execute_script("window.setUnlockedApp('python'); return 'done';")
        time.sleep(1)

        # Select Anomaly / High Risk preset
        driver.execute_script("setFraudPreset('anomaly'); return 'done';")
        time.sleep(2)

        fraud_score = driver.execute_script("return document.getElementById('fraud-score-val') ? document.getElementById('fraud-score-val').textContent.trim() : '0';")
        fraud_tier = driver.execute_script("return document.getElementById('fraud-tier-val') ? document.getElementById('fraud-tier-val').textContent.trim() : '';")
        fraud_verdict = driver.execute_script("return document.getElementById('fraud-verdict-pill') ? document.getElementById('fraud-verdict-pill').textContent.trim() : '';")
        print(f"[+] Fraud Score: {fraud_score}, Tier: {fraud_tier}, Verdict: {fraud_verdict}")
        assert int(fraud_score) > 50, f"Expected high risk score, got: {fraud_score}"

        driver.take_screenshot("playground_fraud_verified.png")

        # ---------------------------------------------
        # TEST 5: App Playground Lockdown / Dynamic Access
        # ---------------------------------------------
        print("\n--- Verifying App Playground Dynamic Access Control ---")
        # App is unlocked for 'python'. Attempting to switch to 'banking' without building it triggers toast
        driver.execute_script("switchPlaygroundApp('banking'); return 'done';")
        time.sleep(0.5)

        toast_msg = driver.execute_script("return document.getElementById('pg-access-toast') ? document.getElementById('pg-access-toast').textContent.trim() : '';")
        print(f"[+] Dynamic Security Toast: '{toast_msg}'")
        assert "RESTRICTED" in toast_msg.upper() or "ACCESS" in toast_msg.upper()

        driver.take_screenshot("playground_lockdown_verified.png")

        # ---------------------------------------------
        # TEST 6: Multi-Image Docker View
        # ---------------------------------------------
        print("\n--- Verifying Multi-Image Docker View ---")
        driver.execute_script("switchWorkspaceTab('comparison'); switchComparisonView('docker'); return 'done';")
        time.sleep(1.5)

        img_cards = driver.execute_script("return document.querySelectorAll('#docker-images-grid .docker-img-card').length;")
        print(f"[+] Docker Images card count: {img_cards}")
        assert img_cards >= 10, f"Expected 10+ docker microservice images, found {img_cards}"

        container_rows = driver.execute_script("return document.querySelectorAll('#docker-containers-tbody tr').length;")
        print(f"[+] Docker Containers row count: {container_rows}")
        assert container_rows >= 3, f"Expected 3+ container execution rows, found {container_rows}"

        driver.take_screenshot("docker_multi_image_verified.png")

        print("\n==============================================")
        print("ALL VERIFICATIONS COMPLETED WITH ZERO ERRORS!")
        print("==============================================")

    finally:
        driver.close()

if __name__ == "__main__":
    main()
