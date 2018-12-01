from . import cryptosystem


class StupidCrypto(cryptosystem.Symmetric):
  """ A cryptosystem that makes no changes to the plaintext. """

  @classmethod
  def get_name(cls):
    return "StupidSymmetric"

  @classmethod
  def get_priority(cls):
    return 0

  def encrypt(self, message):
    return message

  def decrypt(self, message):
    return message

  def gen_key(self):
    return "sym_key"

  def get_key(self):
    return "sym_key"

  def set_key(self, key):
    pass
