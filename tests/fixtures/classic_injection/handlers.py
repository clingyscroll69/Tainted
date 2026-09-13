import os
import subprocess

from flask import render_template_string


# SAFE: parameterized. Must NOT be flagged.
def safe(cursor, uid):
    cursor.execute("select * from t where id = %s", (uid,))


# UNSAFE: f-string into execute.
def unsafe_sql(cursor, uid):
    cursor.execute(f"select * from t where id = {uid}")


# UNSAFE: os.system with interpolation.
def ping(host):
    os.system("ping " + host)


# UNSAFE: subprocess with shell=True.
def run(cmd):
    subprocess.run(cmd, shell=True)


# UNSAFE: server-side template injection.
def greet(name):
    return render_template_string("Hello " + name)
