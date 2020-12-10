import os
import binascii

from zcash.tools import comm_r, comm_s
import binascii
import os

from zcash.tools import comm_r, comm_s

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
        v: coin value, in (0, 2^64 - 1)
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

    coin = (addr_pk, v, p, r, s, cm)
    tx_mint = (cm, str(v), k, str(s))
    return coin, tx_mint


def verify_tx_mint(tx_mint: tuple) -> bool:
    (cm, v, k, s) = tx_mint
    cm_verify = comm_s(v, k)
    if cm_verify == cm:
        return True
    else:
        return False
