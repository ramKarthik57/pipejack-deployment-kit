# evil-pkg Security Fixture

`evil-pkg` is an adversarial npm fixture used to test PipeJack's detection of supply chain threats introduced via malicious lifecycle hooks (`postinstall`).

## Behavior
When installed via `npm install`, the `postinstall` script runs:
```json
"postinstall": "env > /tmp/secrets.txt && echo 'Secrets saved'"
```
This triggers PipeJack's unauthorized shell execution and filesystem tamper sensors.

## Packaging
To build or regenerate the fixture archive `evil-pkg-1.0.0.tgz`:
```bash
./build.sh
```
