import logging
import secrets
import socket

from . import message_passer
from . import protocol_messages as messages


logger = logging.getLogger(__name__)


class Server(message_passer.MessagePasser):
  """ This class handles the main server functionality. """

  def __init__(self, port, crypto_manager):
    """
    Args:
      port: The port to listen on.
      crypto_manager: The CryptoManager instance to use. """
    self.__manager = crypto_manager

    # Create the socket.
    self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.__socket.bind(("", port))
    self.__socket.listen(5)

    logger.info("Server listening on port %d." % (port))

  def __handle_challenge(self, client_sock):
    """ Handles the challenge from the client.
    Args:
      client_sock: Socket that we use to communicate with the client. """
    # Wait for the challenge message.
    challenge_message = self._read_message(messages.ClientChallenge,
                                           client_sock)

    # Create a new context for the client PKC.
    client_key = challenge_message.get("pub_key")
    logger.debug("Got client public key: %s" % (client_key))
    server_pub_context, server_priv_context = self.__manager.get_pkc()
    client_pub_context = server_pub_context.copy_with_key(client_key)

    # Set the session key.
    symmetric_context = self.__manager.get_symmetric()
    session_key = challenge_message.get_encrypted("session_key",
                                                  server_priv_context)
    symmetric_context.set_key(session_key)

    # Extract the challenge value.
    response = challenge_message.get_encrypted("challenge",
                                               server_priv_context)
    # Create a challenge value for the client.
    client_challenge = secrets.token_hex(40)

    # Set the MAC key.
    mac_key = challenge_message.get_encrypted("mac_key",
                                              server_priv_context)
    self.__manager.set_mac_keys(mac_key)
    # This one is not in the manager, and so has to be set manually.
    client_pub_context.set_mac_key(mac_key)

    # Create the response message.
    response_message = messages.ServerChallenge.create( \
        client_pub_context, symmetric_context,
        response=response, challenge=client_challenge)
    # Send the message.
    self._write_message(response_message, client_sock)

    # Receive the session verification message.
    session_message = self._read_message(messages.ClientSessionVerify,
                                         client_sock)

    # Verify the challenge value.
    client_response = session_message.get_encrypted("response",
                                                    symmetric_context)
    if client_response != client_challenge:
      # The client challenge is not valid.
      raise RuntimeError("Challenge failed. Expected %s, got %s." % \
                         (client_challenge, client_response))
    logger.debug("Client challenge passed.")

  def __handshake_with(self, client_sock):
    """ Performs the handshake with a client.
    Args:
      client_sock: The client to perform the handshake with. """
    # Wait for a ClientHello message.
    client_hello = self._read_message(messages.ClientHello, client_sock)

    # Determine what cryptosystems to use.UCSD SoP
    client_pkcs = client_hello.get("pkc")
    client_symmetric = client_hello.get("symmetric")
    if not self.__manager.choose_algorithms(client_pkcs, client_symmetric):
      # We couldn't find a match for one of them.
      raise RuntimeError("Could not find cipher suite match for client.")

    server_public, server_private = self.__manager.get_pkc()
    server_symmetric = self.__manager.get_symmetric()

    # Send the ServerHello message.
    pkc_name = server_public.get_name()
    symmetric_name = server_symmetric.get_name()
    server_pub_key = server_public.get_key()
    server_hello = messages.ServerHello.create(pkc=pkc_name,
                                               symmetric=symmetric_name,
                                               pub_key=server_pub_key)
    self._write_message(server_hello, client_sock)

    # Handle the challenge from the client.
    self.__handle_challenge(client_sock)

    logger.info("Session successfully initialized.")

  def __receive_message(self, client_sock):
    """ Receives and displays a message from the client.
    Args:
      client_sock: The socket to read messages on. """
    # Wait for a message.
    message = self._read_message(messages.SessionMessage, client_sock)

    # Extract the message contents.
    symmetric_context = self.__manager.get_symmetric()
    contents = message.get_encrypted("contents", symmetric_context)

    logger.info("Got message: %s" % (contents))

  def handle_client(self):
    """ Waits for a client to connect, services all the client's requests, and
    then returns when the client disconnects. """
    # First, accept a connection.
    client_sock, addr = self.__socket.accept()
    logger.info("Got connection from %s." % (str(addr)))

    # Perform the handshake.
    self.__handshake_with(client_sock)

    # Receive messages.
    while True:
      try:
        self.__receive_message(client_sock)
      except socket.error:
        logger.info("Client disconnected.")
        break
