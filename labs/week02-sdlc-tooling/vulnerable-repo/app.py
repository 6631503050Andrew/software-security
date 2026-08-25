import sqlite3, hashlib, subprocess, os
from flask import Flask, request

app = Flask(__name__)

# CWE-798: hardcoded credentials / secret (Remediated: load from environment variables)
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89: SQL injection (Remediated: parameterized query)
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: OS command injection (Remediated: remove shell=True and pass list)
    return subprocess.check_output(["ping", "-c", "1", host])

def store_password(pw):
    # CWE-327: weak hash for passwords (Remediated: werkzeug generate_password_hash)
    from werkzeug.security import generate_password_hash
    return generate_password_hash(pw)

if __name__ == "__main__":
    app.run(debug=False)  # CWE-489: debug mode in production (Remediated: set debug=False)

