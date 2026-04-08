
import sqlite3
import os
import subprocess
import operator

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

# Define a dictionary of allowed operations
operations = {
    '+': operator.add,
    '-': operator.sub,
    '*': operator.mul,
    '/': operator.truediv
}

def calculate(num1, op, num2):
    try:
        return operations[op](num1, num2)
    except KeyError:
        return "Invalid operation"
    except ZeroDivisionError:
        return "Cannot divide by zero"

if __name__ == "__main__":
    username = input("Enter username: ")
    print(get_user(username))

    host = input("Enter host to ping: ")
    print(ping_host(host))

    filename = input("Enter filename to read: ")
    print(read_file(filename))

    num1 = float(input("Enter first number: "))
    op = input("Enter operation (+, -, *, /): ")
    num2 = float(input("Enter second number: "))
    print(calculate(num1, op, num2))
