import binascii
import os

from zcash.tools import prf_addr
from zcash.cryptographic_basics import K_enc


def create_address(pp):
    pk_enc, sk_enc = K_enc(pp[2])
    a_sk = binascii.hexlify(os.urandom(256 // 8))
    a_pk = prf_addr(a_sk, b"0" * (256 // 8))
    addr_pk = (a_pk, pk_enc)
    addr_sk = (a_sk, sk_enc)
    return addr_pk, addr_sk


if __name__ == '__main__':
    pp = (1, 1, 1, 1)
    print(create_address(pp))
