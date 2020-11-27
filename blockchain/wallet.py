import hashlib
import base64
from ecdsa import SigningKey, SECP256k1, VerifyingKey
import binascii
import json
from cryptographic_basics import *


class Wallet():
    def __init__(self):
        self._sk, self._pk = K_sig(1)

    @property
    def address(self):
        """
        generate address by pk
        """
        h = hashlib.sha256(self._pk.to_pem())
        return base64.b64encode(h.digest())

    @property
    def pubkey(self):
        """
        return pubkey string
        """
        return self._pk.to_pem()

    def sign(self, msg):
        """
        generate digital signature
        """
        return S_sig(self._sk, msg)


def verify_sign(pubkey: str, msg, signature: bytes):
    return V_sig(pubkey, msg, signature)


class Transaction:
    def __init__(self, sender, receiver, amount):
        if isinstance(sender, bytes):
            sender = sender.decode("utf-8")
        self.sender = sender
        if isinstance(receiver, bytes):
            receiver = receiver.decode('utf-8')
        self.receiver = receiver
        self.amount = amount

    def set_sign(self, pubkey, sign):
        self.pubkey = pubkey
        self.sign = sign
    
    def __repr__(self):
        """
        there are 2 kinds of tx. first is mine to earn, second is to receive
        """
        if self.sender:
            s = self.receiver + " receive $" + str(self.amount) + " from " + self.sender
        else:
            s = self.receiver + " mine to earn $" + str(self.amount)
        return s


class TransactionEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Transaction):
            return obj.__dict__
        

def test_wallet():
    """
    test the function of Wallet
    """
    w = Wallet()
    s = w.sign("111")
    print(w.address)
    print(s)
    print(verify_sign(w.pubkey, "111", s))

if __name__ == '__main__':
    test_wallet()
