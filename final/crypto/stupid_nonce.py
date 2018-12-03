from . import nonce

class StupidNonceGenerator(nonce.NonceGenerator):
  """ Nonce generator for testing that always generates the same value. """

  @classmethod
  def get_name(cls):
    return "StupidNonce"

  def get_length(self):
    return 2

  def generate(self):
    return str(42)

  def get(self):
    return str(42)

class StupidNonceVerifier(nonce.NonceVerifier):
  """ Nonce verifier for testing that always deems a nonce valid. """

  @classmethod
  def get_name(cls):
    return "StupidNonce"

  def verify(self, nonce):
    return True

  def advance(self):
    pass
