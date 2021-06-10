import socket
from contextlib import closing
from flask import Flask, render_template, request
from flask_socketio import SocketIO
from threading import Thread
import secrets
import os
import webview
from subprocess import Popen, PIPE
import atexit


def get_python_path():
    return os.path.split(os.path.abspath(os.path.dirname(os.__file__)))[
        0] + "/python"


def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
key = secrets.token_hex(64)
port = find_free_port()
socketio = SocketIO(app, cors_allowed_origins='*')
service = Thread(target=lambda: socketio.run(
    app, port=port), args=(), kwargs={}, daemon=True)

disassembler = None


def serve():
    print('starting socket io at port {} with key {}'.format(port, key))

    service.start()    # Create a standard webview window
    p = Popen(
        [get_python_path(), os.path.abspath(__file__)],
        shell=True,
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        bufsize=1
    )

    def _kill():
        p.kill()


    atexit.register(_kill)


def stop():
    if service and service.isAlive():
        socketio.stop()


def authenticate(handler):
    def _validate(data):
        return handler(data)
    return _validate


@socketio.on('binary')
@authenticate
def handle_binary_request(data):
    res = None
    function_addresses = data['functions'] if 'functions' in data else None
    with_ins_comments = data['with_ins_comments'] == True if 'with_ins_comments' in data else False
    res = disassembler.disassemble_in_context(
        function_addresses=function_addresses,
        with_ins_comments=with_ins_comments,
    )
    return res


@socketio.on('connect')
def connect():
    print('connected!!')


def create_window():
    def configure():
        window.resize(432, 630)
    window = webview.create_window('L1NNA', 'https://www.l1nna.com',
                                   min_size=(432, 630), on_top=True)
    webview.start(configure)


if __name__ == '__main__':
    create_window()
