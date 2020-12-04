import hashlib
import os
import binascii
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt

from .tools import concat, comm_r, comm_s

# def setup():
#     pk_pour, vk_pour, pp_enc, pp_sig = 1, 1, 1, 1
#     pp = (pk_pour, vk_pour, pp_enc, pp_sig)
#     return pp

# def getAddress(pp):
#     pk_enc, sk_enc = k_enc(pp[2])
#     a_sk = str(binascii.hexlify(os.urandom(256 // 8)), encoding='utf-8')
#     a_pk = prf_addr(a_sk, b'0' * 254)
#     addr_pk = (a_pk, pk_enc)
#     addr_sk = (a_sk, sk_enc)
#     return (addr_pk, addr_sk)

# def k_enc(pp_enc):
#     privKey = generate_eth_key()
#     privKeyHex = privKey.to_hex()
#     pubKeyHex = privKey.public_key.to_hex()
#     return pubKeyHex, privKeyHex

# def k_sig(pp_sig):
#     pass

def mint(pp, v, addr_pk):
    """
    input:
        v: coin value, in (0, z^64 - 1)
    output:
        c: coin
        tx_mint: transaction
    """
    # parse addr_pk
    (a_pk, pk_enc) = addr_pk
    # randomky sample p, r, s
    p = binascii.hexlify(os.urandom(256 // 8))
    r = binascii.hexlify(os.urandom((256 + 128) // 8))
    s = binascii.hexlify(os.urandom(256 // 8))
    
    k = comm_r(r, a_pk, p)
    cm = comm_s(v, k)

    c = (addr_pk, v, p, r, s, cm)
    tx_mint = (cm, v, k, s)
    return c, tx_mint


def verify_mint(tx):
    (cm, v, k, s) = tx
    cm_verify = comm_s(v, k)
    if cm_verify == cm:
        b = 1
    else:
        b = 0
    return b

