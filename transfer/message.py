import json


class Message:
  """ Implements a message that can be sent over the wire.
  Here is a brief description of the protocol:
    - First six characters are the message length, padded with leading zeros,
      which does not include the MAC.
    - Next length characters are JSON-serialized message. """

  @classmethod
  def deserialize_from(cls, message):
    """ Deserializes a message.
    Args:
      message: The message to deserialize.
    Returns:
      The deserialized message, as a new instance of cls. """
    # We don't care about the length. That's only relevant when actually
    # receiving the message, so we can remove it.
    message = message[6:]
    # Extract the message.
    raw_message = json.loads(message)

    # Create the new instance.
    return cls._from_raw(raw_message)

  @classmethod
  def _from_raw(cls, raw_message):
    """ Initializes a new message from a raw one.
    Args:
      raw_message: The message to initialize from. Should be compatible with
                   anything returned by get_raw().
    Returns:
      The instance that it created. """
    raise NotImplementedError("_from_raw() must be implemented by subclass.")

  @classmethod
  def create(cls, *args, **kwargs):
    """ This is the main method of creating a new message.
    Args:
      These can vary depending on the message type.
    Returns:
      The message that it created. """
    raise NotImplementedError("create() must be implemented by subclass.")

  def _get_raw(self):
    """ Gets the raw message, as a dictionary.
    Returns:
      The message as a dictionary. """
    raise NotImplementedError("get_raw() must be implemented by subclass.")

  def get(self, name):
    """ Gets a parameter from the message.
    Args:
      name: The name of the parameter.
    Returns:
      The value of the parameter. """
    return self._get_raw()[name]

  def get_encrypted(self, name, secure_context):
    """ Gets an encrypted parameter from the message.
    Args:
      name: The name of the parameter.
      secure_context: The SecureContext to use when decrypting this field.
    Returns:
      The decrypted field value. """
    field = self._get_raw()[name]
    return secure_context.decrypt(field)

  def serialize(self):
    """
    Returns:
      The message, in string form. This is ready to send over a socket as-is.
    """
    # Serialize the core message.
    raw_message = self._get_raw()
    string_message = json.dumps(raw_message)

    # Build the full message, with the length.
    return "%06d%s" % (len(string_message), string_message)
