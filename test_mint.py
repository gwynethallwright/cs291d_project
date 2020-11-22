from mint import *

def test_comm_r():
    pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
    # parse addr_pk
    (a_pk, pk_enc) = addr_pk
    # randomky sample p, r, s
    p = binascii.hexlify(os.urandom(256 // 8))
    r = binascii.hexlify(os.urandom((256 + 128) // 8))
    s = binascii.hexlify(os.urandom(256 // 8))
    
    print(r, a_pk, p)
    k = comm_r(r, a_pk, p)
    print(len(k), k)

def test_comm_s():
    pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
    # parse addr_pk
    (a_pk, pk_enc) = addr_pk
    # randomky sample p, r, s
    p = binascii.hexlify(os.urandom(256 // 8))
    r = binascii.hexlify(os.urandom((256 + 128) // 8))
    s = binascii.hexlify(os.urandom(256 // 8))
    
    k = comm_r(r, a_pk, p)

    cm = comm_s(v, k)
    print(len(cm), cm)

def test_hash_sha256():
    pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
    # parse addr_pk
    (a_pk, pk_enc) = addr_pk
    # randomky sample p, r, s
    p:bytes = binascii.hexlify(os.urandom(256 // 8))
    r = binascii.hexlify(os.urandom((256 + 128) // 8))
    s = binascii.hexlify(os.urandom(256 // 8))
    a = hash_sha256(a_pk, p)[:128//4]
    print(len(a), a)
    b = hash_sha256(r, bytes(a, encoding='utf-8'))
    print(len(b), b)

def test_mint():
    pp, v, addr_pk = (1, 1, 1, 1), 1, (b'0' * (256 // 4), 1)
    c, tx_mint = mint(pp, v, addr_pk)
    print(c)
    print(tx_mint)

# test_hash_sha256()
# test_comm_r()
# test_comm_s()
test_mint()
