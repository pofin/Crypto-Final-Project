from .cryptosystem import Symmetric
from bitarray import *
import secrets
import math

class RC4(Symmetric):
    def __init__(self, keysize):
        self.keysize = keysize
        self.key = bitarray(keysize)

    def encrypt(self, message):
        """ Encrypts a message.
        Args:
            message (string): The message to encrypt.
        Returns:
            (string) The encrypted message. """
        k = self.key.tobytes()
        msg = bitarray(0)
        msg.frombytes(message.encode('latin-1'))
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + k[i%bits2bytes(self.keysize)])%256
            tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
        m = msg.tobytes()
        c = bitarray(0)
        i = 0
        j = 0
        for it in range(len(m)):
            i = (i+1)%256
            j = (j+s[i])%256
            tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
            xk = s[(s[i]+s[j])%256]
            bkey = bitarray(bin(xk).lstrip('0b'))
            while len(bkey) < 8: bkey.insert(0,False)
            c.extend(bkey^msg[8*it:8*(it+1)])
        return c.tobytes().decode('latin-1')

    def decrypt(self, message):
        """ Decrypts a message.
        Args:
            message (string): The message to decrypt.
        Returns:
            (string) The decrypted message. """
        return self.encrypt(message)

    def gen_key(self):
        """ Generates a 56-bit random key for this cryptosystem.
        Args:
            None.
        Returns:
            (string) The generated key. """
        tmp_key = secrets.randbits(self.keysize)
        for i in range(self.keysize):
            self.key[self.keysize-1-i] = ((tmp_key >> i) & 1)
        return self.key.tobytes().decode("latin-1")

    def set_key(self, new_key):
        """ Sets the key to the argument value
        Args:
            new_key (string): the new key to set. """
        self.key = bitarray()
        self.key.frombytes(new_key.encode("latin-1"))
        self.keylength = self.key.length()

    def get_key(self):
        """ Get the current gen_key
        Args:
            None.
        Returns:
            (string) Current key. """
        return self.key.tobytes().decode("latin-1")

    @classmethod
    def get_name(cls):
        """ Returns the unique name for this cryptosystem """
        return "RC4"

    @classmethod
    def get_priority(cls):
        """ Returns the priority for this cryptosystem """
        return 1


if __name__ == "__main__":
    c = RC4(56)
    a = c.gen_key()
    msg = input("Message => ")
    #print(msg)
    en = c.encrypt(msg)
    print(en)
    dec = c.decrypt(en)
    print(dec)
