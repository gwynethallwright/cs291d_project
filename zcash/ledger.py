import hashlib
import string

from merklelib import MerkleTree
from merklelib.utils import to_hex
from blockchain.chain import BlockChain
from zcash.transaction import TransactionMint, TransactionPour


# reference: merkle tree in golang https://pkg.go.dev/github.com/cbergoon/merkletree#section-sourcefiles
# tx_pour in ledger
# sn on ledger(tree)


class MerkleTreeLedger(MerkleTree):
    def get_path(self, leaf_val: str) -> [(bytes, int)]:
        """
        get a merkle path of leaf
        input:
            leaf_val
        output:
            path: [(hash of leaf, leaf position)]
        """
        node = None
        path = []
        for leaf in self.leaves:
            if self.hasher.hash_leaf(leaf_val) == leaf.hash:
                node = leaf
        if not node:
            return []
        cur = node
        parent = cur.parent
        while parent:
            if cur.hash == parent.left.hash:
                try:
                    path.append((parent.right.hash, 1))  # right leaf
                except AttributeError:
                    pass
            else:
                path.append((parent.left.hash, 0))   # left leaf
            cur = parent
            parent = cur.parent
        return path

    def verify_leaf_path(self, leaf_val: str, path: [(bytes, int)]) -> bool:
        """
        verify a merkle path of leaf
        input:
            leaf_val
            path: [(hash of leaf, leaf position)]
        """
        leaf_hash = self.hasher.hash_leaf(leaf_val)
        for node in path:
            if node[1] == 1:
                leaf_hash = self.hasher.hash_children(leaf_hash, node[0])
            else:
                leaf_hash = self.hasher.hash_children(node[0], leaf_hash)
        return to_hex(leaf_hash) == self.merkle_root

    def verify_leaf(self, leaf) -> bool:
        proof = self.get_proof(leaf)
        return self.verify_leaf_inclusion(leaf, proof)


class Ledger(BlockChain):
    """
    a sequence of transactions
    (BlockChain)

    rt_list stores all past Merkle tree roots

    txMint is appended to the ledger only if u has paid 1 BTC to a backing escrow pool (e.g.,
    the 1 BTC may be paid via plaintext information encoded in txMint). Mint transactions are thus
    certificates of deposit, deriving their value from the backing pool.
    """
    def __init__(self):
        super(Ledger, self).__init__()
        self.rt_list = []

    def add_rt(self, rt):
        self.rt_list.append(rt)


class CMListT:
    """
    CMListT denotes the list of all coin commitments appearing in mint and pour transactions in LedgerT
    """
    def __init__(self):
        self.cm_list_t = []

    def build_from_ledger(self, ledger: Ledger):
        for block in ledger.blocks:
            for tx in block.txs:
                if isinstance(tx, TransactionMint):
                    self.add_cm(tx.tx_mint[0])
                if isinstance(tx, TransactionPour):
                    self.add_cm(tx.tx_pour[3])
                    self.add_cm(tx.tx_pour[4])

    def add_cm(self, cm):
        self.cm_list_t.append(cm)


class TreeCMT:
    """
    TreeCMT denotes a Merkle tree over CMListT and rtT its root
    """
    def __init__(self):
        self.tree_cm_t = MerkleTreeLedger(hashobj=hashfunc)

    def build_from_cm_list(self, cm_list):
        pass

    def add_cm(self, cm):
        self.tree_cm_t.append(cm)

    def get_cm_path(self, cm):
        return self.tree_cm_t.get_path(cm)


class SNListT:
    """
    SNListT denotes the list of all serial numbers appearing in pour transactions in LedgerT
    """
    def __init__(self):
        self.sn_list_t = []

    def build_from_ledger(self, ledger: Ledger):
        for block in ledger.blocks:
            for tx in block.txs:
                if isinstance(tx, TransactionPour):
                    sn_old_1 = tx[1]
                    sn_old_2 = tx[2]
                    self.add_sn(sn_old_1)
                    self.add_sn(sn_old_2)

    def add_sn(self, sn):
        self.sn_list_t.append(sn)

    def verify_sn_inclusion(self, sn):
        return sn in self.sn_list_t


def hashfunc(value):
    """
    hashfunc of merkle tree
    """
    if isinstance(value, str):
        value = value.encode('utf-8')
    return hashlib.sha256(value).hexdigest()


if __name__ == '__main__':
    data = list(string.ascii_letters)
    tree = MerkleTreeLedger(data, hashfunc)

    rt = tree.merkle_root

    # test leaf proof
    proof = tree.get_proof('A')

    assert (tree.verify_leaf_inclusion('A', proof))
    assert (to_hex(tree.hasher.hash_children(tree._root.left.hash, tree._root.right.hash)) == tree.merkle_root)

    # path test
    path = tree.get_path('A')
    res = tree.verify_leaf_path('A', path)

    # tree.append(',')
    # path = tree.get_path(',')
    # res = tree.verify_leaf_path(',', path)
    assert res
