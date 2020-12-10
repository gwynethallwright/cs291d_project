from zcash.cryptographic_basics import D_enc
from zcash.ledger import Ledger, SNListT
from zcash.tools import comm_s, comm_r, prf_sn
from zcash.transaction import TransactionPour


def receive(pp, addr_pk, addr_sk, sn_list: SNListT, ledger: Ledger):
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
    for block in ledger.blocks:
        for tx in block.txs:
            if isinstance(tx, TransactionPour):
                (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, v_pub, info) = tx.tx_pour[:-1]
                (pk_sig, h1, h2, proof_pour, Ciphertext_1, Ciphertext_2, sign) = tx.tx_pour[-1]
                c_1 = verify_cm_and_sn(sk_enc, addr_pk, a_pk, a_sk, sn_list, Ciphertext_1, cm_new_1)
                c_2 = verify_cm_and_sn(sk_enc, addr_pk, a_pk, a_sk, sn_list, Ciphertext_2, cm_new_2)
                if c_1:
                    coin_set.add(c_1)
                if c_2:
                    coin_set.add(c_2)
    return coin_set


def verify_cm_and_sn(sk_enc, addr_pk, a_pk, a_sk, sn_list: SNListT, Ciphertext, cm):
    text_bytes = D_enc(sk_enc, Ciphertext)
    (v, p, r, s) = (text_bytes[0:(64//4)], text_bytes[(64//4):(320//4)], text_bytes[(320//4):(704//4)],
                    text_bytes[(704//4):(960//4)])
    k = comm_r(r, a_pk, p)
    sn = prf_sn(a_sk, p)
    cm_new = comm_s(v, k)
    if (cm == cm_new) and not sn_list.verify_sn_inclusion(sn):
        c = (addr_pk, v, p, r, s, cm)
        return c
    return None
