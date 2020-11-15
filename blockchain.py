import hashlib
from datetime import datetime
import json

from wallet import Transaction, TransactionEncoder, Wallet, verify_sign

MINE_REWARD = 1
DIFFICULTY = 5

class Block:
    """
    block structure
        prev_hash: hash of block of parent
        hash: hash of the block
        timestamp: time of creation
        nounce: random number that makes the hash value meet the condition
        txs: list of transactions
    """
    def __init__(self, prev_hash=None, transactions=[]):
        self.prev_hash = prev_hash
        self.hash = None
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.nounce = None
        self.txs = transactions

    def show(self):
        """
        print a block
        """
        print("hash of prev block is", self.prev_hash)
        print("transactions are", self.txs)
        print("block hash is", self.hash)
        print("\n")


class BlockChain:
    """
    structure of blockchain
        blocks: list of block
    """
    def __init__(self):
        self.blocks = []

    def add_block(self, block):
        self.blocks.append(block)

    def show(self):
        """
        print a blockchain
        """
        for block in self.blocks:
            if block:
                block.show()


class ProofWork():
    """

    """
    def __init__(self, block:Block, wallet, difficult=DIFFICULTY):
        self.difficulty = difficult
        self.block = block
        self.wallet = wallet

    def mine(self):
        # find a random number that makes the hash value meet the condition
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

def get_balance(user, chain: BlockChain):
    balance = 0
    for block in chain.blocks:
        for tx in block.txs:
            if tx.sender == user.address.decode():
                balance -= tx.amount
            elif tx.receiver == user.address.decode():
                balance += tx.amount
    return balance

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

# test_chain()
