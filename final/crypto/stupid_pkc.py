from . import cryptosystem


class StupidCrypto(cryptosystem.Pkc):
  """ A cryptosystem that makes no changes to the plaintext. """

  @classmethod
  def get_name(cls):
    return "StupidPkc"

  @classmethod
  def get_priority(cls):
    return 0

  def encrypt_public(self, message):
    return message

  def decrypt_public(self, message):
    return message

  def encrypt_private(self, message):
    return message

  def decrypt_private(self, message):
    return message

  def get_key_pair(self):
    return "pub_key", "priv_key"

  def copy_with_public_key(self, pub_key):
    return StupidCrypto()
