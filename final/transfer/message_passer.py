import logging
import socket


logger = logging.getLogger(__name__)


class MessagePasser:
  """ Superclass for things that send messages over a socket. """

  def _read_length(self, sock, length):
    """ Reads an entire length of data.
    Args:
      sock: The socket to read from.
      length: The length of the message to read.
    Returns:
      The data that it read. """
    remaining = length
    data = ""
    while remaining > 0:
      data_this_round = sock.recv(remaining).decode("utf-8")
      remaining -= len(data_this_round)
      data += data_this_round

      if len(data_this_round) == 0:
        # Client disconnected.
        raise socket.error("Client disconnected.")

    return data

  def _read_message(self, expected_type, sock):
    """ Waits for and reads the next message from the socket.
    Args:
      expected_type: The class of the message that we expect to receive.
      sock: The socket to read from.
    Returns:
      The message that it read. """
    # Read the length first.
    length = int(self._read_length(sock, 6))
    logger.debug("Reading message of length %d..." % (length))

    # Read the actual message.
    string_message = self._read_length(sock, length)
    logger.debug("Got new message: %s" % (string_message))

    # Deserialize it.
    return expected_type.deserialize_from(string_message)

  def _write_message(self, message, sock):
    """ Writes a message to the socket.
    Args:
      message: The message to write.
      sock: The socket to write to. """
    # Serialize the message.
    string_message = message.serialize()
    logger.debug("Sending message: %s" % (string_message))

    # Send it.
    sock.sendall(string_message.encode("utf-8"))
