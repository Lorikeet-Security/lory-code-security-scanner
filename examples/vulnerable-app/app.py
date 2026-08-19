"""A Flask app doing most things wrong. Fixture only."""

import hashlib
import os
import pickle
import random
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "hunter2-not-a-real-password"
API_KEY = "AKIAIOSFODNN7EXAMPLE"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/user")
def user():
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return cursor.fetchall()


@app.route("/config")
def config():
    return yaml.load(request.data)


@app.route("/session")
def session():
    return pickle.loads(request.cookies.get("state").encode())


@app.route("/fetch")
def fetch():
    return requests.get(request.args.get("url"), verify=False).text


@app.route("/read")
def read():
    return open(os.path.join("/var/data", request.args["name"])).read()


def make_token():
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
