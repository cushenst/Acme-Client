import sys

from flask import Flask, request
import os

app_https = Flask(__name__)
ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
DOMAIN = sys.argv[1]


@app_https.route("/")
def http_challenge():
    return "Hello World!"


if __name__ == '__main__':
    app_https.run(ssl_context=(f'{ASSETS_DIR}/certs/{DOMAIN}/fullchain.pem', f'{ASSETS_DIR}/certs/{DOMAIN}/key.pem'), port=5001,
                  host="0.0.0.0")
