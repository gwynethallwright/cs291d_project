from .circuit import circuit_setup


def setup(security_parameter):
    pk_pour, vk_pour = circuit_setup(security_parameter)
    pp_enc, pp_sig = 1, 1
    pp = (pk_pour, vk_pour, pp_enc, pp_sig)
    return pp
