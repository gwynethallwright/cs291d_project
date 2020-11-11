from flask import Flask, request, render_template
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


@flask_app.route('/new_transaction', methods=['POST'])
def new_transaction():
    transaction_data = request.get_json()
    required_fields = ['sender', 'receiver', 'amount']

    for field in required_fields:
        if not transaction_data.get(field):
            return 'Invalid transaction data.', 404

    blockchain.add_new_transaction(transaction_data)
    return "Success.", 201


@flask_app.route('/submit_transaction', methods=['POST'])
def submit_textarea():
    transaction_sender = request.form['sender']
    transaction_receiver = request.form['receiver']
    transaction_amount = request.form['amount']

    transaction_to_post = {'sender': transaction_sender, 'receiver': transaction_receiver, 'amount': transaction_amount}
    new_transaction_address = "{}/new_transaction".format(NODE_ADDRESS)
    requests.post(new_transaction_address, json=transaction_to_post, headers={'Content-type': 'application/json'})

    return redirect('/')


@flask_app.route('/')
def index():
    return render_template('index.html', title='Simple Blockchain App')
