import unittest

import binascii, os
from zcash import mint, tools

class TestMint(unittest.TestCase):
    def test_comm_r(self):
        pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
        # parse addr_pk
        (a_pk, pk_enc) = addr_pk
        # randomky sample p, r, s
        p = binascii.hexlify(os.urandom(256 // 8))
        r = binascii.hexlify(os.urandom((256 + 128) // 8))
        s = binascii.hexlify(os.urandom(256 // 8))

        print(r, a_pk, p)
        k = tools.comm_r(r, a_pk, p)
        print(len(k), k)


    def test_comm_s(self):
        pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
        # parse addr_pk
        (a_pk, pk_enc) = addr_pk
        # randomky sample p, r, s
        p = binascii.hexlify(os.urandom(256 // 8))
        r = binascii.hexlify(os.urandom((256 + 128) // 8))
        s = binascii.hexlify(os.urandom(256 // 8))

        k = tools.comm_r(r, a_pk, p)

        cm = tools.comm_s(v, k)
        print(len(cm), cm)


    def test_hash_sha256(self):
        pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
        # parse addr_pk
        (a_pk, pk_enc) = addr_pk
        # randomky sample p, r, s
        p: bytes = binascii.hexlify(os.urandom(256 // 8))
        r = binascii.hexlify(os.urandom((256 + 128) // 8))
        s = binascii.hexlify(os.urandom(256 // 8))
        a = tools.hash_sha256(a_pk, p)[:128 // 4]
        print(len(a), a)
        b = tools.hash_sha256(r, bytes(a, encoding='utf-8'))
        print(len(b), b)


    def test_mint(self):
        pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
        c, tx_mint = mint.mint(pp, v, addr_pk)
        print(mint.verify_mint(tx_mint))
        print(c)
        print(tx_mint)


    def test_prf_sn(self):
        x = b'0' * 64
        z = b'0' * 64
        z = int(z.decode(), 16)
        z = hex((z >> 2) | 1 << 254)[2:].encode('utf-8')
        print(len(z), z)
        print(tools.hash_sha256(x, z))

if __name__ == '__main__':
    unittest.main()

