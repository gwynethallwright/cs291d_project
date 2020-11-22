import hashlib
import os
import binascii
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt

def setup():
    pk_pour, vk_pour, pp_enc, pp_sig = 1, 1, 1, 1
    pp = (pk_pour, vk_pour, pp_enc, pp_sig)
    return pp

def getAddress(pp):
    pk_enc, sk_enc = k_enc(pp[2])
    a_sk = str(binascii.hexlify(os.urandom(256 // 8)), encoding='utf-8')
    a_pk = prf_addr(a_sk, b'0' * 254)
    addr_pk = (a_pk, pk_enc)
    addr_sk = (a_sk, sk_enc)
    return (addr_pk, addr_sk)

def k_enc(pp_enc):
    privKey = generate_eth_key()
    privKeyHex = privKey.to_hex()
    pubKeyHex = privKey.public_key.to_hex()
    return pubKeyHex, privKeyHex

def k_sig(pp_sig):
    pass

def mint(pp, v, addr_pk):
    """
    coin value v in (0, z^64 - 1)
    """
    (a_pk, pk_enc) = addr_pk
    p = binascii.hexlify(os.urandom(256 // 8))
    r = binascii.hexlify(os.urandom((256 + 128) // 8))
    s = binascii.hexlify(os.urandom(256 // 8))
    k = comm_r(r, a_pk, p)
    cm = comm_s(v, k)
    c = (addr_pk, v, p, r, s, cm)
    tx_mint = (cm, v, k, s)
    return c, tx_mint


def verify_pour():
    pass

def verify_mint(tx):
    (cm, v, k, s) = tx
    cm_verify = comm_s(v, k)
    if cm_verify == cm:
        b = 1
    else:
        b = 0
    return b

def pour(pp, rt, c_old_1, c_old_2, addr_old_sk_1, addr_old_sk_2, path1, path2, v_new_1, v_new_2, addr_new_pk_1, addr_new_pk_2, v_pub, info):
    """
    input
    - path1: from cm(c_1_old) to root rt
    - path2: from cm(c_2_old) to root rt
    - v_pub: public value
    - info: tx string
    output
    - new coins c_new_1, c_new_2
    - pour transaction tx_pour
    """
    pp_sig = pp[3]

    (addr_old_pk_1, v_old_1, ) = c_old_1
    (a_sk_old_1, pk_enc) = addr_old_sk_1
    (a_sk_old_2, pk_enc) = addr_old_sk_2
    (a_pk_new_1, pk_enc) = addr_new_pk_1
    (a_pk_new_2, pk_enc) = addr_new_pk_2
    
    p_new_1 = binascii.hexlify(os.urandom(256 // 8))
    r_new_1 = binascii.hexlify(os.urandom((256 + 128) // 8))
    s_new_1 = binascii.hexlify(os.urandom(256 // 8))
    k_new_1 = comm_r(r_new_1, a_pk_new_1, p_new_1)
    cm_new_1 = comm_s(v_new_1, k_new_1)

    p_new_2 = binascii.hexlify(os.urandom(256 // 8))
    r_new_2 = binascii.hexlify(os.urandom((256 + 128) // 8))
    s_new_2 = binascii.hexlify(os.urandom(256 // 8))
    k_new_2 = comm_r(r_new_2, a_pk_new_2, p_new_2)
    cm_new_2 = comm_s(v_new_2, k_new_2)

    c_new_1 = (addr_new_pk_1, v_new_1, p_new_1, r_new_1, s_new_1, cm_new_1)
    c_new_2 = (addr_new_pk_2, v_new_2, p_new_2, r_new_2, s_new_2, cm_new_2)

    (pk_sig, sk_sig) = k_sig(pp_sig)
    h_sig = h(pk_sig)
    h1 = prf_pk(a_sk_old_1, '1' + h_sig)
    h2 = prf_pk(a_sk_old_2, '2' + h_sig)
    x = ()
    a = ()
    pi_pour = prove(pk_pour, x, a)
    m = ()



def prf_addr(x:bytes, z:bytes):
    """
    z = {0, 1} * 254
    x = {0, 1} * 256
    """
    return h(x + '00' + z)

def prf_sn(x:bytes, z:bytes):
    """
    z = {0, 1} * 254
    x = {0, 1} * 256
    """
    return h(x + b'01' + z)

def prf_pk(x:bytes, z:bytes):
    """
    z = {0, 1} * 254
    x = {0, 1} * 256
    """
    return h(x + b'10' + z)

def comm_r(r:bytes, a_pk, p):
    """
    r = {0, 1} * (256 + 128)
    a_pk = {0, 1} * 256
    p = {0, 1} * 256
    """
    return h(r, h(a_pk, p)[:128])

def comm_s(v:int, k):
    """
    k = {0, 1} * 256
    """
    v_b = v.to_bytes(64, 'little')
    return h(k, b'0' * 192, v_b)

def h(*args) -> bytes:
    """
    maps a 512-bit input to 256-bit output
    """
    msg = hashlib.sha256()
    input = b''
    for v in args:
        input += v
    msg.update(input)
    return msg.hexdigest()

if __name__ == '__main__':
    # print(k_enc())
    pp = setup()
    (addr_pk, addr_sk) = getAddress(pp)
    print(mint(pp, 1, addr_pk))
