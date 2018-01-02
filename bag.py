"""
# Stylistic re-working of:
#    https://github.com/weex/addrgen/blob/master/addrgen.py


import bag

private_key = '5KVCzJfc1hEYVdbVr2AfaAkRF1rDsqyAMjPArKsDyCZpk7DQK85'
secret = bag.convert_pkey_to_secret(private_key)
bag.get_addr(bag.generate(secret))

bag.get_addr(bag.generate())
"""

import hashlib
import ctypes
import ctypes.util


B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl'))

"""
  Bullshit required for OSX.
"""
class VoidP(ctypes.c_void_p):
    pass

ssl.EC_KEY_new_by_curve_name.restype = VoidP
ssl.BN_bin2bn.restype = VoidP
ssl.BN_new.restype = VoidP
ssl.EC_KEY_generate_key.restype = VoidP
ssl.EC_KEY_get0_group.restype = VoidP
ssl.EC_KEY_get0_private_key.restype = VoidP
ssl.BN_CTX_new.restype = VoidP
ssl.EC_POINT_new.restype = VoidP
"""
  End of bullshit required for OSX.
"""


def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()


def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = B58_DIGITS.index(ch)
        n += digit
    return n


def base58_decode_padded(s):
    pad = 0
    for c in s:
        if c == B58_DIGITS[0]:
            pad += 1
        else:
            break
    h = '%x' % base58_decode(s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode('hex')
    return chr(0) * pad + res


def base58_check_decode(s, version):
    k = base58_decode_padded(s)
    v0, data, check0 = k[0], k[1:-4], k[-4:]
    check1 = dhash(v0 + data)[:4]
    if check0 != check1:
        raise BaseException('checksum error')
    if version != ord(v0):
        raise BaseException('version mismatch')
    return data


def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0, (B58_DIGITS[r]))
    return ''.join(l)


def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return B58_DIGITS[0] * pad + res


def base58_check_encode(s, version):
    vs = chr(version) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)


def get_pubkey(key_pair):
    size = ssl.i2o_ECPublicKey(key_pair, 0)
    mb = ctypes.create_string_buffer(size)
    ssl.i2o_ECPublicKey(key_pair, ctypes.byref(ctypes.pointer(mb)))
    return mb.raw


def get_secret(key_pair):
    bn = ssl.EC_KEY_get0_private_key(key_pair)
    bytes = (ssl.BN_num_bits(bn) + 7) / 8
    mb = ctypes.create_string_buffer(bytes)
    n = ssl.BN_bn2bin(bn, mb)
    return mb.raw.rjust(32, chr(0))


def convert_pkey_to_secret(pkey):
    secret = base58_check_decode(pkey, 128)
    return secret


def generate(secret=None):
    NID_secp256k1 = 714
    key_pair = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
    if secret:
        group = ssl.EC_KEY_get0_group(key_pair)
        priv_key = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
        pub_key = ssl.EC_POINT_new(group)
        ctx = ssl.BN_CTX_new()
        ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
        ssl.EC_KEY_set_private_key(key_pair, priv_key)
        ssl.EC_KEY_set_public_key(key_pair, pub_key)
        ssl.EC_POINT_free(pub_key)
        ssl.BN_CTX_free(ctx)
    else:
        ssl.EC_KEY_generate_key(key_pair)
    return key_pair


def get_addr(key_pair):
    pubkey = get_pubkey(key_pair)
    secret = get_secret(key_pair)
    hash160 = rhash(pubkey)
    addr = base58_check_encode(hash160, 0)
    pkey = base58_check_encode(secret, 128)
    return addr, pkey
