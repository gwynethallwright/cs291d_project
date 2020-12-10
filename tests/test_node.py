import unittest

import time, random

from zcash.node import Node

class TestNode(unittest.TestCase):
    def test_node(self):
        node1 = Node(8000 + random.randrange(0,1000), "node 1")

        node1.start()

        # wait for string
        time.sleep(5)
        node1.print_blockchain()

        time.sleep(10)
        node2 = Node(8000 + random.randrange(0,1000), "node 2")


        node2.start()

        # wait for string
        time.sleep(5)
        node2.print_blockchain()

        print("get balance")
        node1.get_balance()
        node2.get_balance()


        print("minting first coin")
        # node1 mint and pour to send to node2
        tx1 = node1.mint_coin(1)
        node1.broadcast_new_transaction(tx1)
        # waiting for tx broadcast
        time.sleep(30)


        print("minting second coin")
        tx2 = node1.mint_coin(1)
        node1.broadcast_new_transaction(tx2)
        # waiting for tx broadcast
        time.sleep(30)


        print("pouring coin")
        coin_old_1 = list(node1.coin_set)[0]
        coin_old_2 = list(node1.coin_set)[1]
        tx3 = node1.pour_coin(coin_old_1, coin_old_2, node1.addr_sk, node1.addr_sk, 1, 1, node2.addr_pk, node2.addr_pk, 0, "")
        sn_list = [tx3.tx_pour[1], tx3.tx_pour[2]]

        # tx = Transaction(sender=node1.wallet.address, receiver=node2.wallet.address, amount=0.3)
        # sig = node1.wallet.sign(str(tx))
        # tx.set_sign(node1.wallet.pubkey, sig)

        print("broadcasting pouring coin")
        node1.broadcast_new_transaction(tx3)
        # waiting for tx broadcast
        time.sleep(60)

        # node2.receive_coin(node2.addr_pk, node2.addr_sk)
        print("final check")
        node2.get_balance()
        node2.print_blockchain()
        node1.get_balance()
        node1.print_blockchain()


if __name__ == '__main__':
    unittest.main()