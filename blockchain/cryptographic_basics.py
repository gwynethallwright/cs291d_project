import binascii
import hashlib
import os

from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

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
    pk = sk.get_verifying_key()
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


def K_enc(pp_enc):
    private_key = generate_eth_key()
    private_key_hex = private_key.to_hex()
    public_key_hex = private_key.public_key.to_hex()
    return (public_key_hex, private_key_hex)


def E_enc(pk_enc, m):
    if not isinstance(m, bytes):
        m = bytes(m, 'utf-8')
    return encrypt(pk_enc, m)


def D_enc(sk_enc, c):
    return decrypt(sk_enc, c)


def test_enc():
    pk, sk = K_enc(1)
    plaintext_message = b'Hello World'
    encrypted_message = E_enc(pk, plaintext_message)
    decrypted_message = D_enc(sk, encrypted_message)
    if decrypted_message == plaintext_message:
        return True
    return False


if __name__ == '__main__':
    test_sig()
    print(test_enc())
