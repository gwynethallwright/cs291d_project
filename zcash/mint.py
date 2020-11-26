import hashlib
import os
import binascii
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt

from circuit import circuit_prove
from tools import concat

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

    # parse old coin
    (addr_old_pk_1, v_old_1, p_old_1, r_old_1, s_old_1, cm_old_1) = c_old_1
    (addr_old_pk_2, v_old_2, p_old_2, r_old_2, s_old_2, cm_old_2) = c_old_2

    # parse sk of old coin
    (a_sk_old_1, pk_enc) = addr_old_sk_1
    (a_sk_old_2, pk_enc) = addr_old_sk_2

    # parse pk of new coin
    (a_pk_new_1, pk_enc) = addr_new_pk_1
    (a_pk_new_2, pk_enc) = addr_new_pk_2
    
    # create coin and cm
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

    # compute old sn
    sn_old_1 = prf_sn(a_sk_old_1, p_old_1)
    sn_old_2 = prf_sn(a_sk_old_2, p_old_2)
    

    (pk_sig, sk_sig) = k_sig(pp_sig)
    h_sig = hash_sha256(pk_sig)
    h1 = prf_pk(a_sk_old_1, concat(1, h_sig))
    h2 = prf_pk(a_sk_old_2, concat(2, h_sig))
    x = ()
    a = ()
    pi_pour = prove(pk_pour, x, a)
    m = ()

def prf_addr(x:bytes, z:bytes):
    """
    sha256(x||00||z)

    z = {0, 1} * 254
    x = {0, 1} * 256
    """
    z = int(str(z), 16)
    z = hex(z >> 2)[2:].encode('utf-8')
    return hash_sha256(x, z)

def prf_sn(x:bytes, z:bytes):
    """
    sha256(x||01||z)

    z = {0, 1} * 256
    x = {0, 1} * 256
    """
    z = int(str(z), 16)
    z = hex((z >> 2) | 1 << 254)[2:].encode('utf-8')
    return hash_sha256(x, z)

def prf_pk(x:bytes, z:bytes):
    """
    sha256(x||10||256)

    x = {0, 1} * 256
    z = {0, 1} * 254
    """
    z = int(str(z), 16)
    z = hex((z >> 2) | 1 << 255)[2:].encode('utf-8')
    return hash_sha256(x, z)

def comm_r(r:bytes, a_pk, p) -> str:
    """
    input:
        r = {0, 1} * (256 + 128)
        a_pk = {0, 1} * 256
        p = {0, 1} * 256
    output:
        str
    """
    str_h = hash_sha256(a_pk, p)[:128//4]
    return hash_sha256(r, bytes(str_h, encoding='utf-8'))

def comm_s(v:int, k) -> str:
    """
    input:
        k = {0, 1} * 256
    output:
        str
    """
    v_b = bytes(str(v), encoding='utf-8').zfill(64//4)
    return hash_sha256(k, b'0' * (192//4), v_b)

def hash_sha256(*args) -> str:
    """
    maps a 512-bit input to 256-bit output
    input: bytes
    output: str
    """
    msg = hashlib.sha256()
    # caoncat input to 512-bit input
    input = b''
    for v in args:
        if isinstance(v, str):
            v = bytes(v, encoding='utf-8')
        input += v
    msg.update(input)
    return msg.hexdigest()

