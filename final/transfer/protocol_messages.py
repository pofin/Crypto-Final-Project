from . import message


class _ProtocolMessage(message.Message):
  """ Common base class for all messages used in this protocol. """

  @classmethod
  def _from_raw(cls, raw_message):
    # In this case, the encrypted fields are already encrypted, so we can just
    # use the raw message as-is.
    message = cls()
    message._raw = raw_message
    return message

  def _get_raw(self):
    return self._raw


class ClientHello(_ProtocolMessage):
  """ A ClientHello message. """

  @classmethod
  def create(cls, **kwargs):
    """
    This message supports the following parameters:
      pkc: List of PKC algorithms supported by the client.
      symmetric: List of symmetric algorithms supported by the client.
    Returns:
      The created message. """
    pkc = kwargs["pkc"]
    symmetric = kwargs["symmetric"]

    message = cls()
    message._raw = {"pkc": pkc, "symmetric": symmetric}

    return message

class ServerHello(_ProtocolMessage):
  """ A ServerHello message. """

  @classmethod
  def create(cls, **kwargs):
    """
    This messsage supports the following parameters:
      pkc: The name of the PCK algorithm that we want to use.
      symmetric: The name of the symmetric algorithm that we want to use.
      pub_key: The client's public key.
    Returns:
      The created message. """
    pkc = kwargs["pkc"]
    symmetric = kwargs["symmetric"]
    pub_key = kwargs["pub_key"]

    message = cls()
    message._raw = {"pkc": pkc, "symmetric": symmetric, "pub_key": pub_key}

    return message

class ClientChallenge(_ProtocolMessage):
  """ A ClientChallenge message. """

  @classmethod
  def create(cls, server_pub_context, **kwargs):
    """
    Args:
      server_pub_context: SecureContext for server public key.
    This message supports the following parameters:
      challenge: Random string to use as challenge. (encrypted)
      pub_key: The client's public key.
      session_key: Session key generated by client. (encrypted)
      mac_key: A key for the MAC generated by the client. (encrypted)
    Returns:
      The created message. """
    plain_challenge = kwargs["challenge"]
    plain_session_key = kwargs["session_key"]
    plain_mac_key = kwargs["mac_key"]
    pub_key = kwargs["pub_key"]

    # Update the nonce before encrypting fields.
    server_pub_context.update_nonce()

    # Encrypt the challenge and session key.
    challenge = server_pub_context.encrypt(plain_challenge)
    session_key = server_pub_context.encrypt(plain_session_key)
    mac_key = server_pub_context.encrypt(plain_mac_key)

    message = cls()
    message._raw = {"challenge": challenge, "pub_key": pub_key,
                    "session_key": session_key, "mac_key": mac_key}

    return message

class ServerChallenge(_ProtocolMessage):
  """ A ServerChallenge message. """

  @classmethod
  def create(cls, client_pub_context, session_context, **kwargs):
    """
    Args:
      client_pub_context: SecureContext for client public key.
      session_context: SecureContext for the session key.
    This message supports the following parameters:
      challenge: Random string to use as challenge. (encrypted)
      response: The response value to send back to the client. (encrypted)
    Returns:
      The created message. """
    plain_challenge = kwargs["challenge"]
    plain_response = kwargs["response"]

    # Update the nonce before encrypting fields.
    client_pub_context.update_nonce()

    # Encrypt both the challenge and response.
    challenge = client_pub_context.encrypt(plain_challenge)
    response = session_context.encrypt(plain_response)

    message = cls()
    message._raw = {"challenge": challenge, "response": response}

    return message

class ClientSessionVerify(_ProtocolMessage):
  """ A ClientSessionVerify message. """

  @classmethod
  def create(cls, session_context, **kwargs):
    """
    Args:
      session_context: SecureContext for the session key.
    This message supports the following parameters:
      response: The response to the server's challenge. (encrypted)
    Returns:
      The created message. """
    plain_response = kwargs["response"]

    # Update the nonce before encrypting fields.
    session_context.update_nonce()

    # Encrypt the response.
    response = session_context.encrypt(plain_response)

    message = cls()
    message._raw = {"response": response}

    return message

class SessionMessage(_ProtocolMessage):
  """ A standard encrypted message that is send back and forth during the
  session. """

  @classmethod
  def create(cls, session_context, **kwargs):
    """
    Args:
      session_context: SecureContext for the session key.
    This message supports the following parameters:
      contents: Arbitrary data to send to the client. (encrypted) """
    plain_contents = kwargs["contents"]

    # Update the nonce before encrypting fields.
    session_context.update_nonce()

    # Encrypt the data.
    contents = session_context.encrypt(plain_contents)

    message = cls()
    message._raw = {"contents": contents}

    return message
