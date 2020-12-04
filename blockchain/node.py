import pickle
import socket
import threading

from .wallet import Wallet, Transaction, verify_sign

from .blockchain import BlockChain, Block, ProofWork, get_balance

# global variable to save all nodes
NODE_LIST = []

PER_BYTE = 128

class Node(threading.Thread):
    """
    each node is a thread, working on different port of the same computer
    """
    def __init__(self, port, name, host="localhost"):
        threading.Thread.__init__(self, name=name)
        self.host = host
        self.port = port
        self.name = name
        self.wallet = Wallet()
        self.blockchain = None  # every node save a copy of blockchain

    def run(self):
        """
        run a node, init blockchain and handle request from other nodes
        """
        self.init_blockchain()
        NODE_LIST.append({
            "name": self.name,
            "host": self.host, 
            "port": self.port
        })
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(10)
        print(self.name, " running\n")
        while True:
            connection, addr = sock.accept()
            try:
                print(self.name, "handle request")
                self.handle_request(connection)
            except socket.timeout:
                print("timeout")
            except Exception as e:
                print(e, )
            connection.close()


    def init_blockchain(self):
        """
        init the blockchain of current node. if there exist nodes, receive a copy of chain, else, init a genesis block.
        """
        if NODE_LIST:
            # there exist nodes, send 'INIT' message to the first node
            host = NODE_LIST[0]['host']
            port = NODE_LIST[0]['port']
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.send(pickle.dumps('INIT'))
            data = []
            # receive a copy of chain
            while True:
                buf = sock.recv(PER_BYTE)
                if not buf:
                    break
                data.append(buf)
                if len(buf) < PER_BYTE:
                    break
            self.blockchain = pickle.loads(b''.join(data))
            sock.close()
        else:
            # first node, init a genesis block
            self.blockchain = BlockChain()
            print(self.name, "creates genesis block\n")
            genesis_block = Block(None, [])
            pw = ProofWork(genesis_block, self.wallet)
            pw.mine()
            self.blockchain.add_block(genesis_block)

    def print_blockchain(self):
        print(self.name, "blockchain")
        self.blockchain.show()
        print('\n')

    def handle_request(self, connection):
        """
        handle request from other nodes, including 3 message types, new transaction, new block and INIT message
        """
        data = []
        while True:
            buf = connection.recv(PER_BYTE)
            if not buf:
                break
            data.append(buf)
            if len(buf) != PER_BYTE:
                break
        data = pickle.loads(b''.join(data))
        if isinstance(data, Transaction):
            if verify_sign(data.pubkey, str(data), data.sign):
                print(self.name, "verify tx success")
                # receive new transaction msg
                block = Block(prev_hash=self.blockchain.blocks[-1].hash, transactions=[data])
                pw = ProofWork(block, self.wallet)
                pw.mine()
                print(self.name, "generate new block successfully")
                self.blockchain.add_block(block)
                print(self.name, "add new block successfully")
                self.broadcast_new_block(block)
            else:
                print(self.name, "verify tx fail")
        elif isinstance(data, Block):
            # receive new block msg
            print(self.name, "handle new block")
            if self.blockchain.verify_block(data):
                print(self.name, "block verify true")
                for tx in data.txs:
                    if verify_sign(tx.pubkey, str(tx), tx.sign):
                        print(self.name, "verify tx success")
                        self.blockchain.add_block(data)
                        print(self.name, "block add successfully")
                        return
            print(self.name, "block verify false")
        else:
            # a node needs to init, return a copy of chain
            connection.send(pickle.dumps(self.blockchain))

    def get_balance(self):
        print(self.name, " balance ", get_balance(self.wallet, self.blockchain))

    def broadcast_new_block(self, block):
        for node in NODE_LIST:
            if node["host"] == self.host and node["port"] == self.port:
                continue
            print("broadcast block to", node["host"], node["port"])
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((node["host"], node["port"]))
            sock.send(pickle.dumps(block))
            sock.close()
    
    def broadcast_new_transaction(self, transaction):
        for node in NODE_LIST:
            if node["host"] == self.host and node["port"] == self.port:
                continue
            print(self.name, "broadcast tx to", node["name"], node["host"], node["port"])
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((node["host"], node["port"]))
            sock.send(pickle.dumps(transaction))
            sock.close()
