class TransactionPour:
    def __init__(self, rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, value_pub, info,
                 pk_sig, h1, h2, proof_pour, Ciphertext_1, Ciphertext_2, sign):
        tx_pour = (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, value_pub, info,
                   (pk_sig, h1, h2, proof_pour, Ciphertext_1, Ciphertext_2, sign))
        self.tx_pour = tx_pour


class TransactionMint:
    """
    consumes the input bitcoins to produce zerocoins
    """
    def __init__(self, cm, v, k, s):
        tx_mint = (cm, v, k, s)
        self.tx_mint = tx_mint


class Coin:
    def __init__(self, addr_pk, v, p, r, s, cm):
        self.coin = (addr_pk, v, p, r, s, cm)
