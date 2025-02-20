import pickle
import socket
import threading
import os
import binascii

from zcash.setup import setup
from zcash.ledger import Ledger, CMListT, SNListT, TreeCMT
from zcash.create_address import create_address
from zcash.mint import mint, verify_tx_mint
from zcash.pour import pour, verify_tx_pour
from zcash.transaction import TransactionMint, TransactionPour
from zcash.receive import receive
from blockchain.wallet import Wallet, Transaction, verify_sign
from blockchain.chain import Block, ProofWork, get_balance

# global variable for all nodes
security_parameter = binascii.hexlify(os.urandom(256 // 8))
NODE_LIST = []
pp = setup(security_parameter)
PER_BYTE = 128
coin_value_max = 2**64 - 1


class Node(threading.Thread):
    """
    each node is a thread, working on different port of the same computer
    """

    def __init__(self, port, name, host="localhost"):
        threading.Thread.__init__(self, name=name)
        self.host = host
        self.port = port
        self.name = name
        self.addr_pk, self.addr_sk = create_address(pp)
        self.wallet = Wallet()
        self.coin_set = set()
        self.ledger = None  # every node save a copy of blockchain
        self.cm_list = CMListT()
        self.sn_list = SNListT()
        self.tree_cm = TreeCMT()

    def mint_coin(self, value):
        """
        mint to get a mint transaction
        """
        if value > coin_value_max:
            print("mint value is over coin_value_max")
            return
        coin, tx_mint = mint(pp, value, self.addr_pk)
        self.coin_set.add(coin)
        tx = TransactionMint(*tx_mint)
        return tx

    def pour_coin(self, coin_old_1, coin_old_2, addr_old_sk_1, addr_old_sk_2, value_new_1, value_new_2,
                  addr_new_pk_1, addr_new_pk_2, value_pub, info):
        """
        value_pub: to redeem coins or pay transaction fees
        """
        cm_1 = coin_old_1[-1]
        path1 = self.tree_cm.get_cm_path(cm_1)
        cm_2 = coin_old_2[-1]
        path2 = self.tree_cm.get_cm_path(cm_2)
        coin_new_1, coin_new_2, tx_pour = pour(pp, self.tree_cm.tree_cm_t.merkle_root,
                                               coin_old_1, coin_old_2, addr_old_sk_1, addr_old_sk_2,
                                               path1, path2, value_new_1, value_new_2, addr_new_pk_1, addr_new_pk_2, value_pub, info)
        self.coin_set.remove(coin_old_1)
        self.coin_set.remove(coin_old_2)
        tx = TransactionPour(*tx_pour[:-1], *tx_pour[-1])
        return tx

    def receive_coin(self, addr_pk, addr_sk):
        coin_set = receive(pp, addr_pk, addr_sk, self.sn_list, self.ledger)
        self.coin_set = set.union(self.coin_set, coin_set)

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
            self.ledger = pickle.loads(b''.join(data))
            self.cm_list.build_from_ledger(self.ledger)
            self.sn_list.build_from_ledger(self.ledger)
            sock.close()
        else:
            # first node, init a genesis block
            self.ledger = Ledger()
            print(self.name, "creates genesis block\n")
            genesis_block = Block(None, [])
            pw = ProofWork(genesis_block, self.wallet)
            pw.mine()
            self.add_block(genesis_block)

    def add_block(self, block):
        for tx in block.txs:
            if isinstance(tx, TransactionMint):
                self.tree_cm.add_cm(tx.tx_mint[0])
                self.cm_list.add_cm(tx.tx_mint[0])
                self.ledger.add_rt(self.tree_cm.tree_cm_t.merkle_root)
            elif isinstance(tx, TransactionPour):
                self.tree_cm.add_cm(tx.tx_pour[3])
                self.tree_cm.add_cm(tx.tx_pour[4])
                self.cm_list.add_cm(tx.tx_pour[3])
                self.cm_list.add_cm(tx.tx_pour[4])
                self.sn_list.add_sn(tx.tx_pour[1])
                self.sn_list.add_sn(tx.tx_pour[2])
                self.ledger.add_rt(self.tree_cm.tree_cm_t.merkle_root)
        self.ledger.add_block(block)

    def print_blockchain(self):
        print(self.name, "blockchain")
        self.ledger.show()
        print('\n')

    def handle_transaction(self, tx):
        block = Block(prev_hash=self.ledger.blocks[-1].hash, transactions=[tx])
        pw = ProofWork(block, self.wallet)
        pw.mine()
        tx = block.txs[1]
        print(self.name, "generate new block successfully")
        self.add_block(block)
        assert self.ledger.verify_block(block)
        print(self.name, "add new block successfully")
        self.broadcast_new_block(block)

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
                self.handle_transaction(data)
            else:
                print(self.name, "verify tx fail")
        elif isinstance(data, TransactionPour):
            sn_list = [data.tx_pour[1], data.tx_pour[2]]
            if verify_tx_pour(pp, data.tx_pour, sn_list, self.ledger.rt_list[-1]):
                print(self.name, "verify pour tx success")
                # receive new transaction msg
                self.handle_transaction(data)
            else:
                print(self.name, "verify pour tx fail")
        elif isinstance(data, TransactionMint):
            if verify_tx_mint(data.tx_mint):
                print(self.name, "verify mint tx success")
                # receive new transaction msg
                self.handle_transaction(data)
            else:
                print(self.name, "verify mint tx fail")
        elif isinstance(data, Block):
            # receive new block msg
            print(self.name, "handle new block")
            if self.ledger.verify_block(data):
                print(self.name, "block verify true")
                for tx in data.txs:
                    if isinstance(tx, Transaction):
                        if not verify_sign(tx.pubkey, str(tx), tx.sign):
                            return
                    elif isinstance(tx, TransactionMint):
                        if not verify_tx_mint(tx.tx_mint):
                            return
                    elif isinstance(tx, TransactionPour):
                        sn_list = [tx.tx_pour[1], tx.tx_pour[2]]
                        if not verify_tx_pour(pp, tx.tx_pour, sn_list, self.ledger.rt_list[-1]):
                            return
                    print(self.name, "verify tx success")
                self.add_block(data)
                print(self.name, "block add successfully")
                return
            print(self.name, "block verify false")
        else:
            # a node needs to init, return a copy of chain
            connection.send(pickle.dumps(self.ledger))

    def get_balance(self):
        print(self.name, " balance ", get_balance(self.wallet, self.ledger))

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

    def show_coin(self):
        for coin in list(self.coin_set):
            print(self.name, ' coin is', coin)
        print(self.name, ' zcash balance is', self.get_zcash_balance())

    def get_zcash_balance(self):
        balance = 0
        for coin in list(self.coin_set):
            value = coin[1]
            if isinstance(value, bytes):
                value = int(value.decode('utf-8'), 10)
            balance += value
        return balance
