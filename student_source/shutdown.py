from flask import Flask, request
import sys

app_challenge = Flask(__name__)


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


@app_challenge.route("/shutdown")
def shutdown():
    shutdown_server()
    #sys.exit()
    return 'Server shutting down...'


if __name__ == '__main__':
    app_challenge.run(port=5003, host="0.0.0.0")
