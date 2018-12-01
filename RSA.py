from crypto.cryptosystem import Pkc
from bitarray import *
import secrets
import math

class RSA(Pkc):
    def __init__(self, keysize):
        self.keysize = keysize
        self.key = bitarray(keysize)
        self.p = 0
        self.q = 0
        self.e = 0
        self.d = 0
        self.n = 0

    def is_prime_MR(self, n, k):
        """ Tests a number to be prime using the Miller Rabin Primality
        Test
        Args:
            n: number to be tested for primality.
            k: accuracy of the test, number of tests to run
        Returns:
            True if most likely prime, False if not prime. """
        d = n-1
        r = 0
        if (n < 4):
            return True
        while d%2 == 0:
            d = d >> 1
            r += 1
        for i in range(k):
            a = secrets.randbelow(n-2) + 1
            x = pow(a,d,n)
            if x == 1 or x == n-1:
                continue
            for j in range(r-1):
                x = pow(x,2,n)
                if x == n-1:
                    break
            if x == n-1:
                continue
            return False
        return True

    def gcd(self, a, b):
        """ Computes the greatest common denominator
        Args:
            a,b: numbers to compute
        Returns:
            The greatest common denominator """
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.gcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def invert(self, a, m):
        """ Computs a modular inverse
        Args:
            a: the number to invert.
            m: the modular base.
        Returns:
            The modular inverse. """
        g, x, y = self.gcd(a, m)
        if g == 1:
            return x % m

    def rand_prime(self, size):
        """ Generates a random prime number
        Args:
            size: the number of bits in the prime
        Returns:
            The ramdom prime. """
        p = secrets.randbits(size - 1)
        p = (p << 1) + 1
        while self.is_prime_MR(p,10000) == False:
            p += 2
        return p

    def encrypt_public(self, message):
        """ Encrypts a message using the public key.
        Args:
            message: The message to encrypt.
        Returns:
            The encrypted message. """
        enc = pow(message, self.e, self.n)
        return enc

    def encrypt_private(self, message):
        """ Encrypts a message using the private key.
        Args:
            message: The message to encrypt.
        Returns:
            The encrypted message. """
        return pow(message, self.d, self.n)

    def decrypt_public(self, message):
        """ Decrypts a message using the public key.
        Args:
            message: The message to decrypt.
        Returns:
            The decrypted message. """
        return pow(message, self.e, self.n)


    def decrypt_private(self, message):
        """ Decrypts a message using the private key.
        Args:
            message: The message to decrypt.
        Returns:
            The decrypted message. """
        intval = pow(message, self.d, self.n)
        return intval

    def gen_key_pair(self):
        """ Generates a random public-private key pair suitable for this
        cryptosystem.
        Returns:
            The public key and the private key. """
        found_pair = False
        while found_pair == False:
            self.p = c.rand_prime(int(self.keysize/2+1))
            self.q = c.rand_prime(int(self.keysize/2+1))
            self.e = secrets.randbits(self.keysize)
            self.d = self.invert(self.e, (self.p - 1)*(self.q - 1))
            if self.d != None: found_pair = True
        self.n = self.p*self.q
        return self.e, self.d

    def get_key(self):
        """ Get the public and private key materials
        Returns:
            Public key, private key, n """
        return self.e, self.d, self.n

    def set_key(self, ne, nd, nn, np, nq):
        """ Sets the new key for this object
        Args:
            ne: new public key
            nd: new private key
            nn: new modulous
            np: new p
            nq: new q
        Returns:
            None. """
        self.e = ne
        self.d = nd
        self.n = nn
        self.p = np
        self.q = nq
        return

if __name__ == "__main__":
    c = RSA(1024)
    print(c.gen_key_pair())
    msg = int(input("Message => "))
    enc = c.encrypt_public(msg)
    print(enc)
    dec = c.decrypt_private(enc)
    print(dec)
