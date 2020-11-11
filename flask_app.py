from flask import Flask, request
import requests
import simplejson as json
from main import BlockChain

flask_app =  Flask(__name__)
blockchain = BlockChain()


@flask_app.route('/blockchain', methods=['GET'])
def get_blockchain():
    blockchain_data = []
    for block in blockchain.blocks:
        blockchain_data.append(block.__dict__)
    return json.dumps({'length': len(blockchain_data), 'blocks': blockchain_data})
