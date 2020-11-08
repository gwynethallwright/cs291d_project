import hashlib
import base64
from datetime import datetime
from ecdsa import SigningKey, SECP256k1, VerifyingKey
import binascii
import json


MINE_REWARD = 1

class Block:
    """
    
    """
    def __init__(self, prev_hash=None, transactions=[]):
        self.prev_hash = prev_hash
        self.hash = None
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.nounce = None
        self.txs = transactions

    def show(self):
        print("父区块", self.prev_hash)
        print("内容", self.txs)
        print("区块哈希", self.hash)
        print("\n")

class BlockChain:
    def __init__(self):
        self.blocks = []

    def add_block(self, block):
        self.blocks.append(block)

    def show(self):
        for block in self.blocks:
            if block:
                block.show()


class ProofWork():
    def __init__(self, block:Block, wallet, difficult=5):
        self.difficulty = difficult
        self.block = block
        self.wallet = wallet

    def mine(self):
        # PoW
        prefix = '0' * self.difficulty
        i = 0
        while i < 5000000:
            message = hashlib.sha256()
            message.update(str(self.block.txs).encode('utf-8'))
            message.update(str(self.block.prev_hash).encode('utf-8'))
            message.update(self.block.timestamp.encode('utf-8'))
            message.update(str(i).encode('utf-8'))
            digest = message.hexdigest()
            if digest.startswith(prefix):
                self.block.nounce = i
                self.block.hash = digest
                t = Transaction("", self.wallet.address, MINE_REWARD)
                signature = self.wallet.sign(json.dumps(t, cls=TransactionEncoder))
                t.set_sign(self.wallet.pubkey, signature)
                self.block.txs.append(t)
                # return self.block
                break
            i += 1

    def validate(self):
        message = hashlib.sha256()
        message.update(str(self.block.txs).encode('utf-8'))
        message.update(str(self.block.prev_hash).encode('utf-8'))
        message.update(self.block.timestamp.encode('utf-8'))
        message.update(str(self.block.nounce).encode('utf-8'))

        digest = message.hexdigest()
        prefix = '0' * self.difficulty
        return digest.startswith(prefix)


class Wallet():
    def __init__(self):
        self._sk = SigningKey.generate(curve=SECP256k1)
        self._pk = self._sk.get_verifying_key()

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
        h = hashlib.sha256(msg.encode("utf-8"))
        return binascii.hexlify(self._sk.sign(h.digest()))


def verify_sign(pubkey: str, msg, signature: bytes):
    verifier = VerifyingKey.from_pem(pubkey)
    if isinstance(msg, bytes):
        msg = msg.decode()
    h = hashlib.sha256(msg.encode('utf-8'))
    return verifier.verify(binascii.unhexlify(signature), h.digest())


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
            s = "receive:" + str(self.amount)
        else:
            s = "mine to earn:" + str(self.amount)
        return s

class TransactionEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Transaction):
            return obj.__dict__

def get_balance(user, chain: BlockChain):
    balance = 0
    for block in chain.blocks:
        for tx in block.txs:
            if tx.sender == user.address.decode():
                balance -= tx.amount
            elif tx.receiver == user.address.decode():
                balance += tx.amount
    return balance

class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port

def test_wallet():
    """
    test the function of Wallet
    """
    w = Wallet()
    s = w.sign("111")
    print(w.address)
    print(s)
    print(verify_sign(w.pubkey, "111", s))


def test_chain():
    blockchain = BlockChain()

    alice = Wallet()
    bob = Wallet()
    tom = Wallet()
    print("alice's money is", get_balance(alice, blockchain))
    print("bob's money is", get_balance(bob, blockchain))
    print("tom's money is", get_balance(tom, blockchain))

    # alice mine
    new_block1 = Block(transactions=[])
    pw1 = ProofWork(new_block1, alice)
    pw1.mine()
    blockchain.add_block(new_block1)

    print("alice's money is", get_balance(alice, blockchain))

    # alice send 0.3 to tom
    new_tx = Transaction(
        sender=alice.address,
        receiver=tom.address,
        amount=0.3
    )
    sig = tom.sign(str(new_tx))
    new_tx.set_sign(tom.pubkey, sig)

    # bob
    if verify_sign(new_tx.pubkey, str(new_tx), new_tx.sign):
        print("tx success")
        new_block2 = Block(new_block1.hash, [new_tx])
        pw2 = ProofWork(new_block2, bob)
        pw2.mine()
        blockchain.add_block(new_block2)
    else:
        print("tx fail")

    print("alice's money is", get_balance(alice, blockchain))
    print("bob's money is", get_balance(bob, blockchain))
    print("tom's money is", get_balance(tom, blockchain))

    blockchain.show()

# test_wallet()
test_chain()