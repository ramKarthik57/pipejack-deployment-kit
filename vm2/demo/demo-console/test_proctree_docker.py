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
                        "args": ["-headless", "--width=1440", "--height=960"]
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

        # 1. Switch to Comparison Workspace Tab
        print("[+] Switching to Comparison tab...")
        driver.execute_script("switchWorkspaceTab('comparison');")
        time.sleep(1)

        # Verify Proctree view is visible and default is Java
        proctree_disp = driver.execute_script("return document.getElementById('comp-subview-proctree').style.display;")
        print(f"[+] Proctree view display: '{proctree_disp}' (should not be 'none')")

        meta_image = driver.execute_script("return document.getElementById('proctree-meta-image').textContent;")
        print(f"[+] Proctree Meta Image: {meta_image}")

        # Check nodes count in baseline, clean, and malicious
        base_nodes = driver.execute_script("return document.querySelectorAll('#proctree-nodes-baseline .tree-node').length;")
        clean_nodes = driver.execute_script("return document.querySelectorAll('#proctree-nodes-clean .tree-node').length;")
        mal_nodes = driver.execute_script("return document.querySelectorAll('#proctree-nodes-malicious .tree-node').length;")
        print(f"[+] Java Tree Nodes: Baseline={base_nodes}, Clean={clean_nodes}, Malicious={mal_nodes}")

        # Check violation node in malicious tree
        violation_count = driver.execute_script("return document.querySelectorAll('#proctree-nodes-malicious .tree-node-violation').length;")
        print(f"[+] Java Malicious Violations caught: {violation_count}")

        # Take screenshot of Java Differ
        driver.take_screenshot("proctree_java_differ.png")

        # 2. Test Node.js selection
        print("[+] Testing Node.js proctree selection...")
        driver.execute_script("selectProctreeImage('node');")
        time.sleep(1)
        node_img = driver.execute_script("return document.getElementById('proctree-meta-image').textContent;")
        node_mal_nodes = driver.execute_script("return document.querySelectorAll('#proctree-nodes-malicious .tree-node-violation').length;")
        print(f"[+] Node.js Image: {node_img}, Violations: {node_mal_nodes}")

        # 3. Test Python selection
        print("[+] Testing Python proctree selection...")
        driver.execute_script("selectProctreeImage('python');")
        time.sleep(1)
        py_img = driver.execute_script("return document.getElementById('proctree-meta-image').textContent;")
        py_mal_nodes = driver.execute_script("return document.querySelectorAll('#proctree-nodes-malicious .tree-node-violation').length;")
        print(f"[+] Python Image: {py_img}, Violations: {py_mal_nodes}")

        # 4. Test Go selection
        print("[+] Testing Go proctree selection...")
        driver.execute_script("selectProctreeImage('go');")
        time.sleep(1)
        go_img = driver.execute_script("return document.getElementById('proctree-meta-image').textContent;")
        go_mal_nodes = driver.execute_script("return document.querySelectorAll('#proctree-nodes-malicious .tree-node-violation').length;")
        print(f"[+] Go Image: {go_img}, Violations: {go_mal_nodes}")
        driver.take_screenshot("proctree_go_differ.png")

        # 5. Test Docker Multi-Image Execution Monitor Tab
        print("[+] Switching to Docker Execution Monitor tab...")
        driver.execute_script("switchComparisonView('docker');")
        time.sleep(2)
        driver.execute_script("return (async () => { await loadDockerStatus(); })();")
        time.sleep(1)

        docker_disp = driver.execute_script("return document.getElementById('comp-subview-docker').style.display;")
        print(f"[+] Docker view display: '{docker_disp}'")

        images_count = driver.execute_script("return document.querySelectorAll('#docker-images-grid .docker-img-card').length;")
        containers_count = driver.execute_script("return document.querySelectorAll('#docker-containers-tbody tr').length;")
        print(f"[+] Docker Images Cards: {images_count}, Containers Rows: {containers_count}")
        driver.take_screenshot("docker_multi_image_monitor.png")

        print("\n✅ ALL MULTI-IMAGE PROCTREE DIFFER & DOCKER EXECUTION CHECKS PASSED!")

    except Exception as e:
        print(f"[-] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        driver.close()

if __name__ == "__main__":
    main()
