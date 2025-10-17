"""
assignment1_code_sample_fixed.py
Simple mitigations + OWASP category comments.
No external packages beyond what's already imported.
"""

import os
import re
import subprocess
import pymysql
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

# [Fix/A07] Remove hard-coded secrets: use environment variables
# OWASP A07 – Identification & Authentication Failures
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME", "mydb")

def get_user_input():
    # [Fix/A04] Basic allowlist + length cap
    # OWASP A04 – Insecure Design
    raw = input('Enter your name: ').strip()
    if not re.fullmatch(r"[A-Za-z\s\-\']{1,64}", raw):
        raise ValueError("Invalid name format.")
    return raw

def send_email(to, subject, body):
    # [Fix/A03] Avoid shell; do NOT use shell=True
    # OWASP A03 – Injection
    try:
        subprocess.run(
            ["/usr/bin/mail", "-s", subject, to],
            input=(body or "").encode("utf-8"),
            check=True
        )
    except FileNotFoundError:
        print("Mail program not found; skipped.")
    except subprocess.CalledProcessError as e:
        print(f"Email error: {e}")

def get_data():
    # [Fix/A02,A05] HTTPS + timeout + error handling
    # OWASP A02 – Cryptographic Failures; A05 – Security Misconfiguration
    url = "https://insecure-api.com/get-data"  # assume server supports TLS for demo
    try:
        with urlopen(url, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError) as e:
        print(f"Fetch failed: {e}")
        return ""

def save_to_db(data):
    # [Fix/A03] Parameterized query
    # OWASP A03 – Injection
    if not all([DB_HOST, DB_USER, DB_PASSWORD]):
        raise RuntimeError("DB credentials not set (DB_HOST/DB_USER/DB_PASSWORD).")

    conn = None
    try:
        conn = pymysql.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
            connect_timeout=5, read_timeout=5, write_timeout=5
        )
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO mytable (column1, column2) VALUES (%s, %s)",
                (data, "Another Value")
            )
        conn.commit()
    except pymysql.MySQLError as e:
        # [Fix/A05, A09] Minimal error handling/logging
        print(f"DB error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    name = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', name)
