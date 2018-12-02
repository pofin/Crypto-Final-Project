import logging
import secrets
import socket

from . import message_passer
from . import protocol_messages as messages


logger = logging.getLogger(__name__)


class Client(message_passer.MessagePasser):
  """ This class handles the main client functionality. """

  def __init__(self, host, port, crypto_manager):
    """
    Args:
      host: The host to connect to.
      port: The port to connect on.
      crypto_manager: The CryptoManager instance to use. """
    # Create the socket.
    self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the server.
    self.__socket.connect((host, port))

    logger.info("Connected to %s on port %d." % (host, port))

    self.__manager = crypto_manager

    # Perform the handshake.
    self.__handshake()

  def __del__(self):
    logger.debug("Closing socket.")
    self.__socket.close()

  def __perform_challenge(self, server_pub_context):
    """ Generates a secure challenge value, and sends it to the server. Then it
    waits for the server's response and checks that it is valid.
    Args:
      server_pub_context: The public key secure context for the server. """
    # Generate the random challenge value.
    challenge = secrets.token_hex(40)
    # Generate a random MAC key.
    mac_key = secrets.token_hex(40)

    # Generate a session key.
    symmetric_context = self.__manager.get_symmetric()
    session_key = symmetric_context.gen_key()

    # Create the message.
    client_pub_context, client_priv_context = self.__manager.get_pkc()
    message = messages.ClientChallenge.create(server_pub_context,
        challenge=challenge, pub_key=client_pub_context.get_key(),
        session_key=session_key, mac_key=mac_key)
    # Send the message.
    self._write_message(message, self.__socket)

    # Set the MAC key after the message is sent, so the outgoing message uses
    # the old MAC.
    self.__manager.set_mac_keys(mac_key)
    # This one is not in the manager, and so has to be set manually.
    server_pub_context.set_mac_key(mac_key)

    # Wait for the response from the server.
    response_message = self._read_message(messages.ServerChallenge,
                                          self.__socket)

    # Verify the challenge value.
    server_response = response_message.get_encrypted("response",
                                                     symmetric_context)
    if server_response != challenge:
      # The server challenge is not valid.
      raise RuntimeError("Challenge failed. Expected %s, got %s." % \
                         (challenge, server_response))
    logger.debug("Server challenge passed.")

    # Extract the server challenge value.
    response = response_message.get_encrypted("challenge", client_priv_context)

    # Create the session verification message.
    session_message = messages.ClientSessionVerify.create( \
        symmetric_context, response=response)
    # Send the message.
    self._write_message(session_message, self.__socket)

  def __handshake(self):
    """ Performs the handshake with the server. """
    # Get the lists of supported algorithms.
    pkcs = self.__manager.get_supported_pkcs()
    symmetric = self.__manager.get_supported_symmetric()

    # Send the ClientHello message to start the handshake.
    client_hello = messages.ClientHello.create(pkc=pkcs,
                                               symmetric=symmetric)
    self._write_message(client_hello, self.__socket)

    # Read the ServerHello message.
    server_hello = self._read_message(messages.ServerHello, self.__socket)

    # Set the appropriate cipher suite.
    pkc_name = server_hello.get("pkc")
    symmetric_name = server_hello.get("symmetric")
    self.__manager.set_algorithms(pkc_name, symmetric_name)

    # Create a new context for the server PKC.
    server_key = server_hello.get("pub_key")
    logger.debug("Got server public key: %s" % (server_key))
    client_pub_context, _ = self.__manager.get_pkc()
    server_pub_context = client_pub_context.copy_with_key(server_key)

    # Perform the server challenge.
    self.__perform_challenge(server_pub_context)

    logger.info("Session successfully initialized.")

  def send_message(self, data):
    """ Sends an encrypted message to the server.
    Args:
      data: The data to send. """
    symmetric_context = self.__manager.get_symmetric()

    # Create and send the message.
    message = messages.SessionMessage.create(symmetric_context, contents=data)
    self._write_message(message, self.__socket)
