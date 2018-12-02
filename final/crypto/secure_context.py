import copy


class SecureContext:
  """ Defines an encryption/decryption context that also takes care of verifying
  nonces and MACs. """

  def __init__(self, algorithm, nonce_gen, nonce_ver, mac):
    """
    Args:
      algorithm: The symmetric encryption algorithm to use.
      nonce_gen: The nonce generator to use.
      nonce_ver: The nonce verifier to use.
      mac: The MAC algorithm to use. """
    self._algorithm = algorithm
    self._nonce_gen = nonce_gen
    self._nonce_ver = nonce_ver
    self._mac = mac

  def _pad(self, data):
    """ Adds the nonce and MAC to the data.
    Args:
      data: The raw data.
    Returns:
      The data, with the nonce and plaintext appended. """
    nonce = self._nonce_gen.generate()
    with_nonce = data + nonce

    mac = self._mac.generate(with_nonce)
    return with_nonce + mac

  def _verify(self, data):
    """ Takes decrypted data, extracts the nonce and the MAC, and verifies them.
    Args:
      data: The decrypted data, as returned by _pad().
    Returns:
      The base data, without any nonce or MAC. """
    mac_len = self._mac.get_length()
    nonce_len = self._nonce_gen.get_length()

    # Extract and verify the MAC.
    expected_mac = data[-mac_len:]
    field_and_nonce = data[:-mac_len]
    actual_mac = self._mac.generate(field_and_nonce)
    if expected_mac != actual_mac:
      raise ValueError("MAC %s does not match expected MAC %s." % \
                       (actual_mac, expected_mac))

    # Extract and verify the nonce.
    nonce = field_and_nonce[-nonce_len:]
    if not self._nonce_ver.verify(nonce):
      raise ValueError("Nonce %s is invalid." % (nonce))

    # Extract and return the field value.
    return field_and_nonce[:-nonce_len]

  def encrypt(self, data):
    """ Encrypts some data.
    Args:
      data: The data to encrypt.
    Returns:
      The encrypted data, as a string. """
    raise NotImplementedError("encrypt() must be implemented by subclass.")

  def decrypt(self, data):
    """ Decrypts some data.
    Args:
      data: The data to decrypt.
    Returns:
      The decrypted data, as a string. """
    raise NotImplementedError("decrypt() must be implemented by subclass.")

  def get_name(self):
    """
    Returns:
      A unique name for this secure context. """
    # The name is derived by concatenating the names of the cryptosystem, MAC,
    # and nonce.
    name = "%s_%s_%s" % (self._algorithm.get_name(), self._nonce_gen.get_name(),
                         self._mac.get_name())
    return name

  def get_priority(self):
    """
    Returns:
      The priority for this context. A higher priority means that it will favor
      choosing this context during the handshake. """
    # The priority is derived solely from the underlying cryptosystem.
    return self._algorithm.get_priority()

  def get_key(self):
    """
    Returns:
      The currently-set encryption key for this context. """
    raise NotImplementedError("get_key() must be implemented by subclass.")

  def set_mac_key(self, key):
    """ Sets a new key for the MAC.
    Args:
      key: The new key to set. """
    self._mac.set_key(key)

class SymmetricContext(SecureContext):
  """ SecureContext that uses a symmetric encryption algorithm internally. """

  def encrypt(self, data):
    # Add the nonce and MAC.
    padded = self._pad(data)
    # Encrypt the entire thing.
    return self._algorithm.encrypt(padded)

  def decrypt(self, data):
    # Decrypt the data.
    padded = self._algorithm.decrypt(data)
    # Extract and verify the field.
    return self._verify(padded)

  def gen_key(self):
    """ Generates and sets a new symmetric key for this context.
    Returns:
      The key that it generated. """
    return self._algorithm.gen_key()

  def get_key(self):
    return self._algorithm.get_key()

  def set_key(self, key):
    """ Sets a new key for the symmetric algorithm.
    Args:
      key: The new key to set. """
    return self._algorithm.set_key(key)

class PublicKeyContext(SecureContext):
  """ SecureContext that uses the public key from a PKC internally. """

  def encrypt(self, data):
    # Add the nonce and MAC.
    padded = self._pad(data)
    # Encrypt the entire thing.
    return self._algorithm.encrypt_public(padded)

  def decrypt(self, data):
    # Decrypt the data.
    padded = self._algorithm.decrypt_public(data)
    # Extract and verify the field.
    return self._verify(padded)

  def get_key(self):
    public_key, _ = self._algorithm.get_key_pair()
    return public_key

  def copy_with_key(self, pub_key):
    """ Creates a copy of this context with a new public key. All other internal
    state is copied without modification.
    Args:
      pub_key: The new public key to use. """
    # Copy everything.
    nonce_gen = copy.deepcopy(self._nonce_gen)
    nonce_ver = copy.deepcopy(self._nonce_ver)
    mac = copy.deepcopy(self._mac)

    # Clone the algorithm with a new public key.
    algorithm = self._algorithm.copy_with_public_key(pub_key)

    # Create a new instance.
    return PublicKeyContext(algorithm, nonce_gen, nonce_ver, mac)

class PrivateKeyContext(SecureContext):
  """ SecureContext that uses the private key from a PKC internally. """

  def encrypt(self, data):
    # Add the nonce and MAC.
    padded = self._pad(data)
    # Encrypt the entire thing.
    return self._algorithm.encrypt_private(padded)

  def decrypt(self, data):
    # Decrypt the data.
    padded = self._algorithm.decrypt_private(data)
    # Extract and verify the field.
    return self._verify(padded)

  def get_key(self):
    _, private_key = self._algorithm.get_key_pair()
    return private_key
