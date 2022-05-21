import time
import random
import hashlib

#To find inverse Modulo n
def extendedGCD(a, b):
    if a == 0:
        return(b, 0, 1)
    else:
        g, x, y = extendedGCD(b % a, a)
        return (g, (y - (b // a) * x), x)

def mod_inverse(a, n):
    gcd, x, y = extendedGCD(a, n)
    if gcd != 1:
        raise Exception('GCD(a, n) =/= 1 : Modular Multiplicative Inverse Does Not Exist')
    else:
        return x % n

#Fast exponentiation Modulo n
def fastMod(x, y, d):
    r = 1
    x = x % d
    while (y > 0):
        if (y & 1):
            r = (r * x) % d
        y = y >> 1
        x = (x * x) % d
    return r

#Miller - Rabin Prime Checker
def isPrime(n, k = 5):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    #find d such that d * (2 ** s) = (n - 1)
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d >> 1
    assert(2 ** s * d == n - 1)
    for i in range(k):
        a = random.randint(2, n - 1)
        x = fastMod(a, d, n)
        flag = False
        if x == 1:
            continue
        for r in range(s):
            x = fastMod(a, ((2 ** r) * d), n)
            if x == n - 1:
                flag = True
                break
        if flag:
            flag = False
            continue
        else:
            return False
    return True

#Generate n-bit random
def nBit(n):
    return random.randrange(((2 ** (n-1)) + 1), ((2 ** n) - 1))

#Get n-bit prime
def getPrime(n):
    while True:
        candidate = nBit(n)
        if isPrime(candidate):
            return candidate

#Generate primes P, Q such that (P - 1) % Q == 0
def getPQ(L = 512, N = 160):
    d = L - N
    e = 2 ** d
    q = getPrime(N)
    p = q * e
    r = p + 1
    while not isPrime(r):
        p = p + q
        r = p + 1
    p = r
    return p, q

#Generate g = pow(h, ((p - 1) / q), p)
def getG(p, q):
    while True:
        #random h in [2, p - 2]        
        h = random.randint(2, p - 2)
        g = fastMod(h, ((p - 1) // q), p)
        if g != 1:
            return g

#Generate private and public keys
def keyGenDSA(p, q, g):
    #random x between [1, q - 1]
    x = random.randint(1, q - 1)
    y = fastMod(g, x, p)
    return x, y

#Signing
def signM(M, p, q, g, x):
    while True:
        k = random.randint(1, q - 1)
        r = fastMod(g, k, p) % q
        m = int(hashlib.sha1(M.encode()).hexdigest(), 16)
        s = (mod_inverse(k, q) * (m + (x * r))) % q
        if r == 0 or s == 0:
            pass
        else:
            return r, s

#Verify Signature
def verifyRS(M, r, s, p, q, g, y):
    if r < 0 or r > q:
        print('NOT VERIFIED')
        return False
    if s < 0 or s > q:
        print('NOT VERIFIED')
        return False
    w = mod_inverse(s, q)
    m = int(hashlib.sha1(M.encode()).hexdigest(), 16)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (fastMod(g, u1, p) * fastMod(y, u2, p)) % p % q
    if v == r:
        print('VERIFIED')
        return True
    else:
        print('NOT VERIFIED')
        return False

def controllerDSS():
    L = 512
    N = 160
    print('*** DSS PARAMETERS ***')
    p, q = getPQ(L, N)
    print('P : ', p)
    print('Q : ', q)
    g = getG(p, q)
    print('G : ', g)
    PR, PU = keyGenDSA(p, q, g)
    print('Private Key : ', PR)
    print('Public Key : ', PU)
    print('\n*** SIGNING ***')
    #M = input('Enter a Message : ')
    M = 'Hello I am Soumya'
    r, s = signM(M, p, q, g, PR)
    print('R : ', r)
    print('S : ', s)
    print('\n*** VERIFYING ***')
    verifyRS(M, r, s, p, q, g, PU)

if __name__ == '__main__':
    start = time.time()
    controllerDSS()
    end = time.time()
    print('\nTime Elapsed : ', end - start)
