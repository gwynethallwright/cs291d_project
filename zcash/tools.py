import hashlib


def concat(val: int, source: bytes) -> int:
    """
    (1||source) or (10||source)
    """
    source = int(str(source), 16)
    if val == 1:
        return source >> 1 | 1 << 255
    elif val == 2:
        return source >> 2 | 1 << 255
    return source


def prf_addr(x:bytes, z:bytes):
    """
    sha256(x||00||z)

    z = {0, 1} * 254
    x = {0, 1} * 256
    """
    z = int(str(z, encoding='utf-8'), 16)
    z = hex(z >> 2)[2:].encode('utf-8')
    return hash_sha256(x, z)


def prf_sn(sk: bytes, p: bytes):
    """
    sha256(sk||01||p)

    p = {0, 1} * 256 # random
    sk = {0, 1} * 256 # secret key
    """
    p = int(p.decode('utf-8'), 16)
    p = hex((p >> 2) | 1 << 254)[2:].encode('utf-8')
    return hash_sha256(sk, p)

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
    if isinstance(v, str):
        v = int(v)
    v_b = bytes(str(v), encoding='utf-8').zfill(64//4)
    return hash_sha256(k, b'0' * (192//4), v_b)

def CRH(*args):
    return hash_sha256(*args)

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


def tuple_to_str(data: tuple) -> str:
    data_str = []
    for i in data:
        if isinstance(i, int):
            data_str.append(str(i))
        elif isinstance(i, bytes):
            data_str.append(i.decode('utf-8'))
        elif isinstance(i, tuple):
            data_str.append(tuple_to_str(i))
        else:
            data_str.append(i)
    return ','.join(data_str)
