import unittest

from zcash.mint import mint
from zcash.pour import pour
from zcash.ledger import MerkleTreeLedger

class TestPour(unittest.TestCase):
    def test_pour(self):
        tree = MerkleTreeLedger()
        pp, v_1, addr_pk_1 = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
        c_1, tx_mint = mint(pp, v_1, addr_pk_1)
        cm1 = c_1[-1]

        pp, v_2, addr_pk_2 = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
        c_2, tx_mint = mint(pp, v_2, addr_pk_2)
        cm2 = c_2[-1]

        path1 = tree.get_path(cm1)
        path2 = tree.get_path(cm2)
        c_new_1, c_new_2, tx_pour = pour(pp, tree.merkle_root, c_1, c_2, path1, path2)
        print(c_new_1, c_new_2, tx_pour)

if __name__ == '__main__':
    unittest.main()