from flask import Flask, request
import requests
from main import BlockChain

flask_app =  Flask(__name__)
blockchain = BlockChain()
