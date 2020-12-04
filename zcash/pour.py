import binascii
import os

from zcash.tools import comm_r, comm_s, prf_pk, hash_sha256, concat, prf_sn, CRH
from zcash.cryptographic_basics import K_sig, E_enc, S_sig, V_sig
from zcash.circuit import circuit_prove, circuit_verify
from zcash.ledger import MerkleTreeLedger


def pour(pp, rt, c_old_1, c_old_2, addr_old_sk_1, addr_old_sk_2, path1, path2, v_new_1, v_new_2, addr_new_pk_1, addr_new_pk_2, v_pub, info, pk_pour):
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

    p_new_2 = binascii.hexlify(os.urandom(256 // 8))
    r_new_2 = binascii.hexlify(os.urandom((256 + 128) // 8))
    s_new_2 = binascii.hexlify(os.urandom(256 // 8))
    k_new_2 = comm_r(r_new_2, a_pk_new_2, p_new_2)

    cm_new_1 = comm_s(v_new_1, k_new_1)
    cm_new_2 = comm_s(v_new_2, k_new_2)

    c_new_1 = (addr_new_pk_1, v_new_1, p_new_1, r_new_1, s_new_1, cm_new_1)
    c_new_2 = (addr_new_pk_2, v_new_2, p_new_2, r_new_2, s_new_2, cm_new_2)

    # compute ciphertext, the encryption of the plaintext under pk
    Ciphertext_1 = E_enc(pk_enc, (v_new_1, p_new_1, r_new_1, s_new_1))
    Ciphertext_2 = E_enc(pk_enc, (v_new_2, p_new_2, r_new_2, s_new_2))

    # compute old sn
    sn_old_1 = prf_sn(a_sk_old_1, p_old_1)
    sn_old_2 = prf_sn(a_sk_old_2, p_old_2)
    

    (pk_sig, sk_sig) = K_sig(pp_sig)
    h_sig = CRH(pk_sig)
    h1 = prf_pk(a_sk_old_1, concat(1, h_sig))
    h2 = prf_pk(a_sk_old_2, concat(2, h_sig))
    x_pub = (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, v_pub, h_sig, h1, h2)  # public input of circuir of pour
    a_private = (path1, path2, c_old_1, c_old_2,
                 addr_old_sk_1, addr_old_sk_2, c_new_1, c_new_2)    # private input of circuir of pour
    proof_pour = circuit_prove(pk_pour, x_pub, a_private)
    msg = (x_pub, proof_pour, info, Ciphertext_1, Ciphertext_2)
    sign = S_sig(sk_sig, msg)
    tx_pour = (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, v_pub, info, (pk_sig, h1, h2, proof_pour, Ciphertext_1, Ciphertext_2, sign))
    return c_new_1, c_new_2, tx_pour


def verify_tx_pour(pp, tx_pour, ledger: MerkleTreeLedger, vk_pour):
    (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, v_pub, info,
     (pk_sig, h1, h2, proof_pour, Ciphertext_1, Ciphertext_2, sign)) = tx_pour
    if not ledger.verify_leaf(sn_old_1) or not ledger.verify_leaf(sn_old_2) or ledger.merkle_root != rt:
        return 0
    h_sig = CRH(pk_sig)
    x_pub = (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, v_pub, h_sig, h1, h2)
    msg = (x_pub, proof_pour, info, Ciphertext_1, Ciphertext_2)
    return V_sig(pk_sig, msg, sign) and circuit_verify(vk_pour, x_pub, proof_pour)

