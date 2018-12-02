import math
import secrets

from . import nonce


class SequentialNonceGenerator(nonce.NonceGenerator):
  """ Simple nonce that starts at a random value, and then increments it
  indefinitely. """

  @classmethod
  def get_name(cls):
    return "SequentialNonce"

  def __init__(self, length):
    """
    Args:
      length: Length in bits of the nonce. """
    self.__length = length
    self.__hex_length = (self.__length + 3) // 4

    # Pick a random initial value.
    self.__nonce = secrets.randbits(self.__length)

    # Maximum nonce value.
    self.__max_nonce = pow(2, self.__length + 1) - 1

  def get_length(self):
    return self.__hex_length

  def generate(self):
    self.__nonce += 1
    self.__nonce %= self.__max_nonce

    return self.get()

  def get(self):
    expected_length = self.get_length()
    nonce = "%x" % (self.__nonce)
    # Pad the nonce so the length is consistent.
    return "0" * (expected_length - len(nonce)) + nonce

  def set_state(self, state):
    """ Sets the state of the nonce generator.
    Args:
      state: The current state to set. """
    self.__nonce = state

class SequentialNonceVerifier(nonce.NonceGenerator):
  """ Verifier for sequential nonces. It will always accept the first value it
  receives, and then expect it to increment from there. """

  @classmethod
  def get_name(cls):
    return "SequentialNonce"

  def __init__(self, length):
    """
    Args:
      length: Length in bits of the nonce. """
    # Internally, we use a generator to produce the "expected" output.
    self.__generator = SequentialNonceGenerator(length)
    self.__initialized = False

  def verify(self, my_nonce):
    # Convert to an integer.
    int_nonce = int(my_nonce, base=16)

    if not self.__initialized:
      # This is the first value. Use it to set the generator state.
      self.__generator.set_state(int_nonce)
      self.__initialized = True

      return True

    # Check that the value matches.
    expected = self.__generator.get()
    return my_nonce == expected

  def advance(self):
    if not self.__initialized:
      # If it's not initialized, do nothing.
      return

    self.__generator.generate()
