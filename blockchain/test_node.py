#!/usr/bin/env python
# coding: utf-8

import time

from .node import *

node1 = Node(8002, "node 1")


node1.start()

# wait for string
time.sleep(5)
node1.print_blockchain()

time.sleep(10)
node2 = Node(8003, "node 2")


node2.start()

# wait for string
time.sleep(5)
node2.print_blockchain()


node1.get_balance()


node2.get_balance()


tx = Transaction(sender=node1.wallet.address, receiver=node2.wallet.address, amount=0.3)
sig = node1.wallet.sign(str(tx))
tx.set_sign(node1.wallet.pubkey, sig)


node1.broadcast_new_transaction(tx)
# waiting for tx broadcast
time.sleep(30)

node2.print_blockchain()


node2.get_balance()


node1.get_balance()


node1.print_blockchain()
