from secrets import randbelow
from math import log
import os


def generate_prime(bit_length):
    bit_length = int(bit_length)
    assert bit_length > 0
    return int(os.popen(' '.join(['openssl', 'prime', '-generate', '-bits', str(bit_length)])).read())


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a, b):
    return a*b//gcd(a, b)


def ctf(a,b):
    return lcm(a-1, b-1)


def inverse(a, n):
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    assert not r > 1
    if t < 0 :
        t = t + n
    return t


def generate_e(l):
    maximum = int(min(36, log(l,2)))
    minimum = int(min(log(l, 2)/2, 18))
    bit_length = randbelow(maximum-minimum)+minimum
    e = generate_prime(bit_length=bit_length)

    t = 0
    while l%e==0:
        t+=1
        assert t<10
        e = generate_prime(bit_length=bit_length)

    return e


def create_key(p=None, q=None, bit_length=1024):
    if not p:
        p = generate_prime(bit_length)
    if not q:
        q = generate_prime(bit_length)
    l = ctf(p, q)
    e = generate_e(l)
    d = inverse(e, l)
    n = p*q
    assert (e*d)%l == 1
    return e, d, n


def padd(block, size):
    cont = 10**size
    return int(''.join(str(cont + ord(c)) \
            for c in block))


def unpadd(block, size):
    cont = 10**size
    s = []
    while block>0:
        n = block%cont
        block = block//(cont*10)
        s.append(chr(n))
    return ''.join(reversed(s))


def encrypt(x, pub_key, size=6):
    res = []
    i = 0
    e, n = pub_key
    block_size = len(str(n))//(size+1)
    while len(x)>i:
        if len(x)-i>block_size:
            res.append(str(pow(padd(x[i:i+block_size], size=size), e, n)))
        else:
            res.append(str(pow(padd(x[i:], size=size), e, n)))
        i+=block_size
    return '/'.join(res)


def decrypt(y, key, size=6):
    d, n = key
    return ''.join(unpadd(pow(int(block), d, n), size=size) for block in y.split('/'))


# Example usage

e, d, n = create_key(bit_length=2048)
print('keylength: ', len(str(n)))

with open('test.txt', 'r') as foo:
    s = foo.read()

se = encrypt(s, (e, n), size=3)
print('unencrypted length: ', len(s))
print('encrypted length: ', len(se))
t = decrypt(se, (d, n), size=3)

print('Passed test: ', all((c1==c2) for c1,c2 in zip(s,t))) # True if unencrypted and decrypted are equal


