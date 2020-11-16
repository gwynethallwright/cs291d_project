import hashlib
import random
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt

def setup():
    pp = (pk_pour, vk_pour, pp_enc, pp_sig)
    return pp

def getAddress(pp):
    pk_enc, sk_enc = k_enc()
    a_sk = random.getrandbits(random.randrange(256)).to_bytes(256, "little")
    a_pk = prf_addr(a_sk, b'0' * 254)
    addr_pk = (a_pk, pk_enc)
    addr_sk = (a_sk, sk_enc)
    return (addr_pk, addr_sk)

def k_enc():
    privKey = generate_eth_key()
    privKeyHex = privKey.to_hex()
    pubKeyHex = privKey.public_key.to_hex()
    return pubKeyHex, privKeyHex

def mint(pp, v, addr_pk):
    """
    coin value v in (0, z^64 - 1)
    """
    (a_pk, pk_enc) = addr_pk
    p = random.getrandbits(random.randrange(256)).to_bytes(256, "little")
    r = random.getrandbits(random.randrange(256)).to_bytes(256 + 128, "little")
    s = random.getrandbits(random.randrange(256)).to_bytes(256, "little")
    k = comm_r(r, a_pk, p)
    cm = comm_s(v, k)
    c = (addr_pk, v, p, r, s, cm)
    tx_mint = (v, k, s, cm)
    return c, tx_mint

def prf_addr(x:bytes, z:bytes):
    """
    z = {0, 1} * 254
    x = {0, 1} * 256
    """
    return h(x + b'00' + z)

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
    return msg.digest()
