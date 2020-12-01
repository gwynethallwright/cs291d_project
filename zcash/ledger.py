import hashlib
import string

from merklelib import MerkleTree
from merklelib.utils import to_hex

# reference: merkle tree in golang https://pkg.go.dev/github.com/cbergoon/merkletree#section-sourcefiles


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
                path.append((parent.right.hash, 1))  # right leaf
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
    assert res
