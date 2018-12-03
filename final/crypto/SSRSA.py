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
        r = secrets.randbelow(self.n)
        en1 = pow(r, self.e, self.n)
        h2 = bitarray(SHA1.SHA1(hex(r)))
        #h2 = bitarray(0)
        #h2.frombytes(h1)
        m = bitarray(0)
        m.frombytes(message.encode("latin-1"))
        dif = h2.length() - (m.length()%h2.length())
        for i in range(dif): m.insert(0, False)
        st = ""
        for i in range(int(m.length()/h2.length())): st += (h2^m[i*h2.length():(i+1)*h2.length()]).tobytes().decode("latin-1")
        return en1, st

    def encrypt_private(self, message):
        """ Encrypts a message using the private key.
        Args:
            message (string): The message to encrypt.
        Returns:
            (int, string) The encrypted message. """
        r = secrets.randbelow(self.n)
        en1 = pow(r, self.d, self.n)
        h1 = SHA1.SHA1(hex(r))
        h2 = bitarray(0)
        h2.frombytes(bytes.fromhex(h1[2:]))
        m = bitarray(0)
        m.frombytes(message.encode("latin-1"))
        dif = h2.length() - (m.length()%h2.length())
        for i in range(dif): m.insert(0, False)
        st = ""
        for i in range(int(m.length()/h2.length())): st += (h2^m[i*h2.length():(i+1)*h2.length()]).tobytes().decode("latin-1")
        return en1, st

    def decrypt_public(self, message):
        """ Decrypts a message using the public key.
        Args:
            message (int, string): The message to decrypt.
        Returns:
            (string) The decrypted message. """
        r = pow(message[0], self.e, self.n)
        h1 = SHA1.SHA1(hex(r))
        h2 = bitarray(0)
        h2.frombytes(bytes.fromhex(h1[2:]))
        m = bitarray(0)
        m.frombytes(message[1].encode("latin-1"))
        st = ""
        for i in range(int(m.length()/h2.length())): st += (h2^m[i*h2.length():(i+1)*h2.length()]).tobytes().decode("latin-1")
        i = 0
        while st[i] == '\x00': i+=1
        return st[i:]

    def decrypt_private(self, message):
        """ Decrypts a message using the private key.
        Args:
            message (int, string): The message to decrypt.
        Returns:
            (string) The decrypted message. """
        r = pow(message[0], self.d, self.n)
        h2 = bitarray(SHA1.SHA1(hex(r)))
        #h2 = bitarray(0)
        #h2.frombytes(h1)
        m = bitarray(0)
        m.frombytes(message[1].encode("latin-1"))
        st = ""
        for i in range(int(m.length()/h2.length())): st += (h2^m[i*h2.length():(i+1)*h2.length()]).tobytes().decode("latin-1")
        i = 0
        while st[i] == '\x00': i+=1
        return st[i:]

if __name__ == "__main__":
    c = SSRSA(512)
    print(c.gen_key_pair())
    m = input("Message => ")
    en = c.encrypt_public(m)
    #print(en)
    de = c.decrypt_private(en)
    print(de)
