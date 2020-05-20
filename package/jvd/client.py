from flask import Flask, render_template, request
from flask_socketio import SocketIO
from threading import Thread
import secrets
from jvd import get_disassembler
from jvd.disassembler import DisassemblerAbstract
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
key = secrets.token_hex(64)
socketio = SocketIO(app, cors_allowed_origins='*')
service = Thread(target=lambda: socketio.run(app), args=(), kwargs={})

disassembler = get_disassembler()
disassembler: DisassemblerAbstract


def serve():
    print('starting socket io at port {} with key {}'.format(5000, key))
    service.start()


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
