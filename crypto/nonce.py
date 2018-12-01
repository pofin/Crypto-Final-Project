class NonceGenerator:
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

class NonceVerifier:
  """ Interface for verifying nonce values. This maintains state, so it should
  be used with only one client. """

  def verify(self, nonce):
    """ Verifies the nonce value.
    Args:
      nonce: The nonce to verify.
    Returns:
      True if the nonce is valid, false otherwise. """
    raise NotImplementedError("verify() must be implemented by subclass.")
