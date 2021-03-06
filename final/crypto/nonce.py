class Nonce:
  """ Common interface for nonce generators and verifiers. """

  @classmethod
  def get_name(cls):
    """
    Returns:
      A unique name for this nonce type. """
    raise NotImplementedError("get_name() must be implemented by subclass.")

class NonceGenerator(Nonce):
  """ Interface for generating nonce values. """

  def get_length(self):
    """
    Returns:
      The length of the nonces produced by this class, in bytes. """
    raise NotImplementedError("get_length() must be implemented by subclass.")

  def generate(self):
    """
    Returns:
      A new generated nonce value. """
    raise NotImplementedError("generate() must be implemented by subclass.")

  def get(self):
    """
    Gets the current nonce without generating a new one.
    Returns:
      The current nonce value. """
    raise NotImplementedError("get() must be implemented by subclass.")

class NonceVerifier(Nonce):
  """ Interface for verifying nonce values. This maintains state, so it should
  be used with only one client. """

  def advance(self):
    """ Advances the verifier state. """
    raise NotImplementedError("advance() must be implemented by subclass.")

  def verify(self, nonce):
    """ Verifies the nonce value.
    Args:
      nonce: The nonce to verify.
    Returns:
      True if the nonce is valid, false otherwise. """
    raise NotImplementedError("verify() must be implemented by subclass.")
