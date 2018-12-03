from .cryptosystem import Pkc
from bitarray import *
import secrets
import math

class GoldwasserMicali(Pkc):
    def __init__(self, keysize):
        self.keysize = keysize
        self.key = bitarray(keysize)
        self.p = 0
        self.q = 0
        self.n = 0
        self.x = 0

    def is_prime_MR(self, n, k):
        """ Tests a number to be prime using the Miller Rabin Primality
        Test
        Args:
            n (int): number to be tested for primality.
            k (int): accuracy of the test, number of tests to run
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
            a,b (int): numbers to compute
        Returns:
            (int) The greatest common denominator """
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.gcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def invert(self, a, m):
        """ Computs a modular inverse
        Args:
            a (int): the number to invert.
            m (int): the modular base.
        Returns:
            (int) The modular inverse. """
        g, x, y = self.gcd(a, m)
        if g == 1:
            return x % m

    def rand_prime(self, size):
        """ Generates a random prime number
        Args:
            size (int): the number of bits in the prime
        Returns:
            (int) The ramdom prime. """
        p = secrets.randbits(size - 1)
        p = (p << 1) + 1
        while self.is_prime_MR(p,100) == False:
            p += 2
        return p

    def legendre_symbol(self, a, p):
        """ Calculates the legendre symbol of a number
        Args:
            a (int): the number to be evaluated
            p (int): the prime modulus of the system
        Returns:
            (int) The legendre symbol of (a|p) """
        
        legendre = pow(a,(p-1)//2,p)
        if(legendre == p-1):
            return -1
        else:
            return legendre

    def is_quad_res(self, x, p, q):
        """ Checks whether or not a number is a quadratic residue in N=p*q
        Args:
            x (int): the number to be checked. Required to be less than p & q
            p (int): one of two distict prime numbers used in N=p*q
            q (int): the other distict prime number used in N=p*q
        Returns:
            True if the number is QR and false if the number is QNR """

        xModP = x % p
        xModQ = x % q

        return (pow(xModP,(p-1)//2,p) == 1 and pow(xModQ,(q-1)//2,q) == 1)

    def encrypt_public(self, message):
        """ Encrypts a message using the public key.
        Args:
            message (string): The message to encrypt.
        Returns:
            (string) The encrypted message. """
        bit_message = bitarray()
        bit_message.frombytes(message.encode("latin-1"))

        cypher = list()
        for bit in bit_message:
            randNumber = secrets.randbelow(self.n)
            while(randNumber == self.p or randNumber == self.q):
                randNumber = secrets.randBelow(self.n)
            if not bit:
                cipherNumber = ((randNumber ** 2) * pow(self.x, 0)) % self.n
            else:
                cipherNumber = ((randNumber ** 2) * pow(self.x, 1)) % self.n
            cypher.append(cipherNumber)
        cypherString = ""
        for num in cypher:
            cypherString = cypherString + str(num) + ","
        return cypherString.rstrip(',')

    def decrypt_private(self, message):
        """ Decrypts a message using the private key.
        Args:
            message (string): The message to decrypt.
        Returns:
            (string) The decrypted message. """

        plaintext = bitarray()
        messageList = message.split(',')
        for string in messageList:
            num = int(string)
            if(self.is_quad_res(num, self.p, self.q)):
                plaintext.append(False)
            else:
                plaintext.append(True)

        return plaintext.tobytes().decode("latin-1")

    def gen_key_pair(self):
        """ Generates a random public-private key pair suitable for this
        cryptosystem.
        Returns:
            (list[int,int], [int,int]) The public key[x, modulus] and the private
            key[p, q]. """
        found_pair = False
        while found_pair == False:
            self.p = self.rand_prime(int(self.keysize/2+1))
            self.q = self.rand_prime(int(self.keysize/2+1))
            self.x = secrets.randbelow(min(self.p, self.q))
            if (self.legendre_symbol(self.x, self.p) == -1 and self.legendre_symbol(self.x, self.q) == -1): found_pair = True
        self.n = self.p*self.q
        return (self.x, self.n), (self.p, self.q)

    def get_key_pair(self):
        """ Get the public and private key materials
        Returns:
            (Returns:
            (list[int,int], [int,int]) The public key[x, modulus] and the private
            key[p, q]. """
        return (self.x, self.n), (self.p, self.q)

    def set_key_pair(self, npub, npriv):
        """ Sets the new key for this object
        Args:
            npub (list[int, int]): new public key[e, modulus]
            npriv (list[int, int]): new private key[p, q]
        Returns
            None. """
        self.x = npub[0]
        self.n = npub[1]
        self.p = npriv[0]
        self.q = npriv[1]
        return

    def copy_with_public_key(self, pub_key):
        """ Creates a copy of this same cryptosystem, but with a new public key.
        The private key is set to None.
        Args:
          pub_key (list[int,int]): The public key to use.
        Returns:
          The new cryptosystem. """
        rc = GoldwasserMicali(self.keysize)
        rc.set_key_pair(pub_key, (None, None))
        return rc

    @classmethod
    def get_name(cls):
        """ Returns the unique name for this cryptosystem """
        return "GoldwasserMicali"

    @classmethod
    def get_priority(cls):
        """ Returns the priority for this cryptosystem """
        return 3


if __name__ == "__main__":
  c = GoldwasserMicali(1024)
  print(c.gen_key_pair())
  msg = "100101010100100111001001010001001100101010"
  enc = c.encrypt_public(msg)
  print(enc)
  dec = c.decrypt_private(enc)
  print(dec)
