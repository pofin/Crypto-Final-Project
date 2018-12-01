class Symmetric:
  """ Defines a common interface for all symmetric cryptosystems. """

  def encrypt(self, message):
    """ Encrypts a message.
    Args:
      message: The message to encrypt.
    Returns:
      The encrypted message. """
    raise NotImplementedError("encrypt() must be implemented by subclass.")

  def decrypt(self, message):
    """ Decrypts a message.
    Args:
      message: The message to decrypt.
    Returns:
      The decrypted message. """
    raise NotImplementedError("decrypt() must be implemented by subclass.")

  def gen_key(self):
    """ Generates an appropriate-length random key for this cryptosystem.
    Returns:
      The generated key. """
    raise NotImplementedError("gen_key() must be implemented by subclass.")

class Pkc:
  """ Defines a common interface for all PKC's. """

  def encrypt_public(self, message):
    """ Encrypts a message using the public key.
    Args:
      message: The message to encrypt.
    Returns:
      The encrypted message. """
    raise NotImplementedError( \
        "encrypt_public() must be implemented by subclass.")

  def encrypt_private(self, message):
    """ Encrypts a message using the private key.
    Args:
      message: The message to encrypt.
    Returns:
      The encrypted message. """
    raise NotImplementedError( \
        "encrypt_private() must be implemented by subclass.")

  def decrypt_public(self, message):
    """ Decrypts a message using the public key.
    Args:
      message: The message to decrypt.
    Returns:
      The decrypted message. """
    raise NotImplementedError( \
        "decrypt_public() must be implemented by subclass.")

  def decrypt_private(self, message):
    """ Decrypts a message using the private key.
    Args:
      message: The message to decrypt.
    Returns:
      The decrypted message. """
    raise NotImplementedError( \
        "decrypt_private() must be implemented by subclass.")

  def gen_key_pair(self):
    """ Generates a random public-private key pair suitable for this
    cryptosystem.
    Returns:
      The public key and the private key. """
    raise NotImplementedError( \
        "gen_key_pair() must be implemented by subclass.")
