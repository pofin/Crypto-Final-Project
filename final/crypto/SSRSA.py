from RSA import *
import SHA1
import secrets

class SSRSA(RSA):
    def encrypt_public(self, message):
        """ Encrypts a message using the public key.
        Args:
            message (string): The message to encrypt.
        Returns:
            (int, string) The encrypted message. """
        r = secrets.randbelow(2**self.keysize)
        en1 = pow(r, self.e, self.n)
        h1 = SHA1.SHA1(hex(r))
        h2 = bitarray(0)
        print(r,h1)
        h2.frombytes(bytes.fromhex(h1[2:]))
        m = bitarray(0)
        m.frombytes(message.encode("latin-1"))
        while m.length() < h2.length(): m.insert(0, False)
        return en1, (h2^m).tobytes().decode("latin-1")

    def encrypt_private(self, message):
        """ Encrypts a message using the private key.
        Args:
            message (string): The message to encrypt.
        Returns:
            (int, string) The encrypted message. """
        enc = pow(self.__to_int(message), self.d, self.n)
        return self.__from_int(enc)

    def decrypt_public(self, message):
        """ Decrypts a message using the public key.
        Args:
            message (int, string): The message to decrypt.
        Returns:
            (string) The decrypted message. """
        dec = pow(self.__to_int(message), self.e, self.n)
        return self.__from_int(dec)

    def decrypt_private(self, message):
        """ Decrypts a message using the private key.
        Args:
            message (int, string): The message to decrypt.
        Returns:
            (string) The decrypted message. """
        r = pow(message[0], self.d, self.n)
        h1 = SHA1.SHA1(hex(r))
        h2 = bitarray(0)
        print(r,h1)
        h2.frombytes(bytes.fromhex(h1[2:]))
        m = bitarray(0)
        m.frombytes(message[1].encode("latin-1"))
        st = (h2^m).tobytes().decode("latin-1")
        i = 0
        while st[i] == '\x00': i+=1
        return st[i:]

if __name__ == "__main__":
    c = SSRSA(128)
    print(c.gen_key_pair())
    m = input("Message => ")
    en = c.encrypt_public(m)
    #print(en)
    de = c.decrypt_private(en)
    print(de)
