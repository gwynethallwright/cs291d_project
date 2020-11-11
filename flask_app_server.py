import datetime
import json
import requests
from flask import render_template, redirect, request
from flask_app import flask_app

NODE_ADDRESS = 'http://127.0.0.1:8000'
GET_SUCCESS_CODE = 200

blockchain_data = []

def get_blockchain_data():
    get_blockchain_address = "{}/chain".format(NODE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == GET_SUCCESS_CODE:
        blockchain_content = []
        blockchain = json.loads(response.content)
        for block in blockchain['chain']:
            for transaction in block['txs']:
                # transaction['index'] = block['index']
                transaction['hash'] = block['previous_hash']
                blockchain_content.append(tx)
        blockchain_data = sorted(blockchain_content, key=lambda k: k['timestamp'], reverse=True)
