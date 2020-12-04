from .cryptographic_basics import D_enc
from .ledger import MerkleTreeLedger
from .tools import comm_s, comm_r, prf_sn


def receive(pp, addr_pk, addr_sk, ledger: MerkleTreeLedger):
    """
    inputs:
    – public parameters pp
    – recipient address key pair (addrpk, addrsk)
    – the current ledger L
    outputs: set of received coins
    """
    (a_pk, pk_enc) = addr_pk
    (a_sk, sk_enc) = addr_sk
    coin_set = set()
    # Calculate your own coins from the ledger
    for tx_pour in ledger:
        (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, v_pub, info,
         (pk_sig, h1, h2, proof_pour, Ciphertext_1, Ciphertext_2, sign)) = tx_pour
        c_1 = verify_cm_and_sn(sk_enc, addr_pk, a_pk, a_sk, ledger, Ciphertext_1, cm_new_1)
        c_2 = verify_cm_and_sn(sk_enc, addr_pk, a_pk, a_sk, ledger, Ciphertext_2, cm_new_2)
        if c_1:
            coin_set.add(c_1)
        if c_2:
            coin_set.add(c_2)


def verify_cm_and_sn(sk_enc, addr_pk, a_pk, a_sk, ledger, Ciphertext, cm):
    (v, p, r, s) = D_enc(sk_enc, Ciphertext)
    k = comm_r(r, a_pk, p)
    sn = prf_sn(a_sk, p)
    if (cm == comm_s(v, k)) and ledger.verify_leaf(sn):
        c = (addr_pk, v, p, r, s, cm)
        return c
    return None
