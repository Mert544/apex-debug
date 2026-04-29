"""Deliberately buggy code for testing Apex Debug patterns."""

import os
import pickle
import sqlite3


def process_user_input(user_data):
    result = eval(user_data)
    return result


def run_shell_command(cmd):
    os.system(cmd)


def load_user_session(data):
    return pickle.loads(data)


def query_database(db_path, user_id, user_input):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id} AND name = '{user_input}'")
    return cursor.fetchall()


def check_value(x):
    if x == None:
        return "missing"
    return x


def risky_operation(data, cmd):
    try:
        process_user_input(data)
    except:
        pass
    import subprocess
    subprocess.run(cmd, shell=True)


def unused_calc(a, b):
    result = a + b
    temp = result * 2
    return temp


if __name__ == "__main__":
    result = process_user_input("1 + 1")
    print(result)
