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
      The encrypted data. """
    raise NotImplementedError("encrypt() must be implemented by subclass.")

  def decrypt(self, data):
    """ Decrypts some data.
    Args:
      data: The data to decrypt.
    Returns:
      The decrypted data. """
    raise NotImplementedError("decrypt() must be implemented by subclass.")

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

class PublicKeyContext(SecureContext):
  """ SecureContext that uses the public key from a PKC internally. """

  def encrypt(self, data):
    # Add the nonce and MAC.
    padded = self._pad(data)
    # Encrypt the entire thing.
    return self._algorithm.encrypt_public(padded)

  def decrypt(self, data):
    # Decrypt the data.
    padded = self._algorithm.decrypt_public(padded)
    # Extract and verify the field.
    return self._verify(padded)

class PrivateKeyContext(SecureContext):
  """ SecureContext that uses the private key from a PKC internally. """

  def encrypt(self, data):
    # Add the nonce and MAC.
    padded = self._pad(data)
    # Encrypt the entire thing.
    return self._algorithm.encrypt_private(padded)

  def decrypt(self, data):
    # Decrypt the data.
    padded = self._algorithm.decrypt_private(padded)
    # Extract and verify the field.
    return self._verify(padded)

