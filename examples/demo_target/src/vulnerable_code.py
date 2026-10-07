"""Intentionally-vulnerable source for the white-box (SAST) demo.

This stands in for application source a `--repo` / `rampart sast` scan would see. Each
function contains a classic sink pattern the native AST scanner flags; several share a CWE
with the runtime (DAST) demo flaws so the SAST<->DAST correlation can link them. NOT imported
or executed by the demo server — it is sample source for static analysis only.
"""
import hashlib
import os
import pickle
import subprocess

import requests  # noqa: F401 (sample import; not installed/executed)

API_KEY = "rampartDEMOhardcodedSECRET1234567890"   # CWE-798 hardcoded secret


def ping(host):                                          # CWE-78 command injection
    return subprocess.run("ping -c1 " + host, shell=True, capture_output=True)


def run_cmd(user_input):                                 # CWE-78 via os.system
    os.system("echo " + user_input)


def get_order(cursor, order_id):                         # CWE-89 SQL injection
    cursor.execute(f"SELECT * FROM orders WHERE id = '{order_id}'")
    return cursor.fetchone()


def fetch(url):                                          # CWE-918 SSRF
    return requests.get(url, timeout=5)


def load_profile(blob):                                  # CWE-502 insecure deserialization
    return pickle.loads(blob)


def compute(expr):                                       # CWE-95 code injection
    return eval(expr)


def hash_password(pw):                                   # CWE-327 weak hash
    return hashlib.md5(pw.encode()).hexdigest()


def read_file(request_path):                             # CWE-22 path traversal
    with open("/var/data/" + request_path) as fh:
        return fh.read()


def start():                                             # CWE-489 debug server
    from flask import Flask
    app = Flask(__name__)
    app.run(debug=True)
