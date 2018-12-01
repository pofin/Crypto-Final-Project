class Cryptosystem:
  """ Common interface for all cryptosystems. """

  @classmethod
  def get_name(cls):
    """
    Returns:
      A unique name for this cryptosystem. """
    raise NotImplementedError("get_name() must be implemented by subclass.")

  @classmethod
  def get_priority(cls):
    """
    Returns:
      A numerical priority for this algorithm. The higher the priority, the more
      it will favor using this algorithm during the handshake. """
    raise NotImplementedError("get_priority() must be implemented by subclass.")

class Symmetric(Cryptosystem):
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
    """ Generates an appropriate-length random key for this cryptosystem. The
    key will be set for future use.
    Returns:
      The generated key. """
    raise NotImplementedError("gen_key() must be implemented by subclass.")

  def get_key(self):
    """ Gets the key that is currently in use.
    Returns:
      The key. """
    raise NotImplementedError("get_key() must be implemented by subclass.")

  def set_key(self, key):
    """ Sets the key that is currently in use.
    Args:
      key: The key to set. """
    raise NotImplementedError("set_key() must be implemented by subclass.")

class Pkc(Cryptosystem):
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
    cryptosystem. The keys will be set for future use.
    Returns:
      The public key and the private key. """
    raise NotImplementedError( \
        "gen_key_pair() must be implemented by subclass.")

  def get_key_pair(self):
    """
    Returns:
      Currently set public and private key. """
    raise NotImplementedError( \
        "get_key_pair() must be implemented by subclass.")

  def set_key_pair(self, public_key, private_key):
    """ Sets a new key pair for this cryptosystem. It automatically assumes that
    the key pair is valid.
    Args:
      public_key: The public key to set.
      private_key: The corresponding private key. """
    raise NotImplementedError("set_key_pair() must be implemented by subclass.")

  def copy_with_public_key(self, pub_key):
    """ Creates a copy of this same cryptosystem, but with a new public key.
    What happens to the private key is not specified.
    Args:
      pub_key: The public key to use.
    Returns:
      The new cryptosystem. """
    raise NotImplementedError( \
        "copy_with_public_key() must be implemented by subclass.")
