"""
def G_sig(security_parameter):


def K_sig(pp_sig):


def S_sig(sk_sig, m):


def V_sig(pk_sig, m, sigma):


def G_enc(security_parameter):


def K_enc(pp_enc):


def E_enc(pk_enc, m):


def D_enc(sk_enc, c):
"""

from ecdsa import SigningKey, SECP256k1, VerifyingKey
import hashlib
import os
import binascii

# def KeyGen(C_pour):
#     """
#     output:
#         pk_pour, vk_pour
#     """

# def G_sig(security_parameter):
#     """
#     output:
#         pp_sig
#     """
security_parameter = os.urandom(256 // 8)

def K_sig(pp_sig):
    """
    output:
        pk_sig, sk_sig
    """
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.get_verifying_key().to_pem()
    return sk, pk


def S_sig(sk_sig, m: str) -> bytes:
    h = hashlib.sha256(m.encode('utf-8'))
    return binascii.hexlify(sk_sig.sign(h.digest()))


def V_sig(pk_sig, m, sigma: bytes) -> bool:
    verifier = VerifyingKey.from_pem(pk_sig)
    if isinstance(m, bytes):
        m = m.decode('utf-8')
    h = hashlib.sha256(m.encode('utf-8'))
    return verifier.verify(binascii.unhexlify(sigma), h.digest())


def test_sig():
    sk, pk = K_sig(1)
    m = '1'
    sign = S_sig(sk, m)
    print(V_sig(pk, m, sign))

if __name__ == '__main__':
    test_sig()
