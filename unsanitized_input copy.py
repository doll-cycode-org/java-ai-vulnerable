import sqlite3
import os
import subprocess
import ast

# Vulnerable to SQL injection
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# Vulnerable to command injection
def ping_host(host):
    output = os.popen("ping -c 1 " + host).read()
    return output

# Vulnerable to path traversal
def read_file(filename):
    with open("/var/data/" + filename, "r") as f:
        return f.read()

# Fixed: Using ast.literal_eval for safe evaluation of literals
def calculate(expression):
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        return "Invalid expression"

if __name__ == "__main__":
    username = input("Enter username: ")
    print(get_user(username))

    host = input("Enter host to ping: ")
    print(ping_host(host))

    filename = input("Enter filename to read: ")
    print(read_file(filename))

    expr = input("Enter expression to evaluate: ")
    print(calculate(expr))
