import ctypes
import os.path
lib_name = "/../circuit-pour/build/src/libpour.so"
dllabspath = os.path.dirname(os.path.abspath(__file__)) + lib_name
libpour = ctypes.CDLL(dllabspath)


"""
def circuit_setup(security_parameter):
    return pk_pour, vk_pour

def circuit_prove(pk_pour, x, a):
    return proof_pour

def circuit_verify(vk_pour, x, proof_pour) -> bool:
"""


def circuit_setup(security_parameter):
    pk_pour, vk_pour = 1, 1
    libpour.c_generate_proof(1,0,0,0,0,0)
    with open("pk.bin", mode='rb') as file:
        pk_pour = file.read()
    with open("vk.bin", mode='rb') as file:
        vk_pour = file.read()
    return pk_pour, vk_pour


def circuit_prove(pk_pour, x_pub, a_private):
    print(x_pub, flush=True)
    print(a_private, flush=True)
    print("PRINTED", flush=True)
    (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, value_pub, h_sig, h1, h2) = x_pub
    (path1, path2, coin_old_1, coin_old_2, addr_old_sk_1, addr_old_sk_2, coin_new_1, coin_new_2) = a_private

    return _circuit_prove(pk_pour, value_pub,coin_new_1[1],coin_new_2[1],coin_old_1[1],coin_old_2[1])

def _circuit_prove(pk_pour, *args):
    #coin: (addr_pk, v, p, r, s, cm)
    print("=============")
    print(*args)
    print("=============")
    proof_pour = 1
    with open("pk.bin", mode='wb') as file:
        file.write(pk_pour)
    libpour.c_generate_proof(0,*args)
    
    with open("proof.bin", mode='rb') as file:
        proof_pour = file.read()
    return proof_pour

def circuit_verify(vk_pour, x_pub, proof_pour) -> bool:
    (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, value_pub, h_sig, h1, h2) = x_pub
    return _circuit_verify(vk_pour, proof_pour, value_pub)

def _circuit_verify(vk_pour, proof_pour, *args) -> bool:
    print("=============")
    print(*args)
    print("=============")
    with open("vk.bin", mode='wb') as file:
        file.write(vk_pour)
    with open("proof.bin", mode='wb') as file:
        file.write(proof_pour)
    return libpour.c_verify_proof(*args)
