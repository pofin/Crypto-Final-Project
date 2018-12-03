from .cryptosystem import Pkc
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

    def __to_int(self, message):
      """ Converts a string message to an int.
      Args:
        message: The string message to convert.
      Returns:
        The message in int form. """
      # First, convert the message to a byte array.
      byte_message = message.encode("latin-1")
      if len(byte_message) > self.keysize // 8:
        raise ValueError("Message of length %d must be less than key size." % \
                         (len(byte_message)))

      # Now, convert to an int.
      return int.from_bytes(byte_message, byteorder="little", signed=False)

    def __from_int(self, message):
      """ Converts an int message to a string.
      Args:
        message: The int message to convert.
      Returns:
        The message in string form. """
      # First, convert the message to a byte array.
      length = (message.bit_length() + 7) // 8
      byte_message = message.to_bytes(length, byteorder="little", signed=False)
      # Now, convert to a string.
      return byte_message.decode("latin-1")

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

    def is_prime_MR_Det(self, n):
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
        for a in range(2, int(2*(math.log(n)**2))):
            x = pow(a,d,n)
            test = False
            for s in range(0,r-1):
                if pow(a,d*(2**r),n) == n-1:
                    test = True
                    break
            if x == 1 or x == n-1:
                continue
            if test == True:
                return False
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
        while self.is_prime_MR(p,10000) == False:
            p += 2
        return p

    def encrypt_public(self, message):
        """ Encrypts a message using the public key.
        Args:
            message (string): The message to encrypt.
        Returns:
            (string) The encrypted message. """
        enc = pow(self.__to_int(message), self.e, self.n)
        return self.__from_int(enc)

    def encrypt_private(self, message):
        """ Encrypts a message using the private key.
        Args:
            message (string): The message to encrypt.
        Returns:
            (string) The encrypted message. """
        enc = pow(self.__to_int(message), self.d, self.n)
        return self.__from_int(enc)

    def decrypt_public(self, message):
        """ Decrypts a message using the public key.
        Args:
            message (string): The message to decrypt.
        Returns:
            (string) The decrypted message. """
        dec = pow(self.__to_int(message), self.e, self.n)
        return self.__from_int(dec)

    def decrypt_private(self, message):
        """ Decrypts a message using the private key.
        Args:
            message (string): The message to decrypt.
        Returns:
            (string) The decrypted message. """
        dec = pow(self.__to_int(message), self.d, self.n)
        return self.__from_int(dec)

    def gen_key_pair(self):
        """ Generates a random public-private key pair suitable for this
        cryptosystem.
        Returns:
            (list[int,int],int) The public key[e, modulus] and the private
            key. """
        found_pair = False
        while found_pair == False:
            self.p = self.rand_prime(int(self.keysize/2+1))
            self.q = self.rand_prime(int(self.keysize/2+1))
            self.n = self.p*self.q
            self.e = secrets.randbits(self.keysize)
            while self.e > self.n:
                self.e = secrets.randbits(self.keysize - 1)
                print(self.e, self.n)
            self.d = self.invert(self.e, (self.p - 1)*(self.q - 1))
            if self.d != None: found_pair = True
        return (self.e, self.n), self.d

    def get_key_pair(self):
        """ Get the public and private key materials
        Returns:
            (list[int,int],int) Public key[e, modulus], private key """
        return [self.e, self.n], self.d

    def set_key_pair(self, npub, npriv):
        """ Sets the new key for this object
        Args:
            npub (list[int, int]): new public key[e, modulus]
            npriv (int): new private key
        Returns
            None. """
        self.e = npub[0]
        self.d = npriv
        self.n = npub[1]
        return

    def copy_with_public_key(self, pub_key):
        """ Creates a copy of this same cryptosystem, but with a new public key.
        The private key is set to None.
        Args:
          pub_key (list[int,int]): The public key to use.
        Returns:
          The new cryptosystem. """
        rc = RSA(self.keysize)
        rc.set_key_pair(pub_key, None)
        return rc

    @classmethod
    def get_name(cls):
        """ Returns the unique name for this cryptosystem """
        return "RSA"

    @classmethod
    def get_priority(cls):
        """ Returns the priority for this cryptosystem """
        return 1

if __name__ == "__main__":
    c = RSA(128)
    c.set_key_pair(list((111405670540845042695715069191615509637, 231038902772913249059615478169528941503)),30427868915927038427378379900132143189)
    msg = input("Message => ")
    enc = c.encrypt_public(msg)
    print(enc)
    dec = c.decrypt_private(enc)
    print(dec)
