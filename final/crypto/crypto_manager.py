import logging


logger = logging.getLogger(__name__)


class CryptoManager:
  """ Manages a suite of cryptographic algorithms. """

  def __init__(self):
    # Dictionary of symmetric cryptographic contexts, organized by name.
    self.__symmetric_contexts = {}
    # Dictionary of public key cryptographic contexts, organized by name.
    self.__public_contexts = {}
    # Dictionary of private key cryptographic contexts, organized by name.
    self.__private_contexts = {}

    # These are the contexts that we have chosen for a particular client.
    self.__private_context = None
    self.__public_context = None
    self.__symmetric_context = None

  def add_symmetric_context(self, context):
    """ Adds a new symmetric key secure context to the manager.
    Args:
      context: The SymmetricContext to add. """
    name = context.get_name()
    logger.debug("Adding symmetric context: %s" % (name))

    self.__symmetric_contexts[name] = context

  def add_pkc_contexts(self, public_context, private_context):
    """ Adds a new PKC secure context pair to the manager.
    Args:
      public_context: The PublicContext to add.
      private_context: The corresponding PrivateContext to add. """
    # Sanity check for corresponding contexts.
    name = public_context.get_name()
    private_name = private_context.get_name()
    if name != private_name:
      raise ValueError("PKC context names '%s' and '%s' must match." % \
                       (name, private_name))
    logger.debug("Adding PKC contexts: %s" % (name))

    self.__public_contexts[name] = public_context
    self.__private_contexts[name] = private_context

  def choose_algorithms(self, client_pkc, client_symmetric):
    """ Chooses the cipher suite to use for communicating with a client.
    Args:
      client_pkc: The list of PKCs supported by the client.
      client_symmetric: The list of symmetric ciphers supported by the client.
    Returns:
      True if it found matches for everything, false otherwise.
    """
    def find_match(client_contexts, server_contexts):
      """ Finds the highest-priority match between client and server contexts.
      Args:
        client_contexts: List of (priority, context) tuples supported by the
                         client, sorted by priority.
        server_contexts: Dictionary of contexts supported by the server.
      Returns:
        The highest-priority context that matches between both of them, or None
        if no contexts matched. """
      # This list is sorted from low to high, so we want to reverse it.
      client_contexts = client_contexts[::-1]

      for priority, context in client_contexts:
        name = context.get_name()

        if name in server_contexts:
          # We have a match.
          return context

      # There are no matches.
      return None

    # First, match the names of all our supported contexts.
    client_public_contexts = []
    client_private_contexts = []
    for pkc_name in client_pkc:
      if pkc_name not in self.__public_contexts:
        # We don't support this one, but the client does.
        continue

      public = self.__public_contexts[pkc_name]
      private = self.__private_contexts[pkc_name]

      priority = public.get_priority()
      client_public_contexts.append((priority, public))
      client_private_contexts.append((priority, private))

    client_symmetric_contexts = []
    for symmetric_name in client_symmetric:
      if symmetric_name not in self.__symmetric_contexts:
        # We don't support this one, but the client does.
        continue

      symmetric = self.__symmetric_contexts[symmetric_name]

      priority = symmetric.get_priority()
      client_symmetric_contexts.append((priority, symmetric))

    # Sort each by priority.
    client_public_contexts.sort(key=lambda x: x[0])
    client_private_contexts.sort(key=lambda x: x[0])
    client_symmetric_contexts.sort(key=lambda x: x[0])

    # Now, find the highest-priority match for each.
    self.__public_context = find_match(client_public_contexts,
                                       self.__public_contexts)
    self.__private_context = find_match(client_private_contexts,
                                        self.__private_contexts)
    self.__symmetric_context = find_match(client_symmetric_contexts,
                                          self.__symmetric_contexts)

    if (not self.__public_context or not self.__private_context or \
        not self.__symmetric_context):
      # We didn't find a match for at least one.
      return False

    logger.info("Choosing cryptosystems: PKC: %s, Symmetric: %s" % \
                (self.__public_context.get_name(),
                 self.__symmetric_context.get_name()))
    return True

  def set_algorithms(self, pkc_name, symmetric_name):
    """ Sets the algorithms that we would like to use.
    Args:
      pkc_name: The name of the PKC algorithm to use.
      symmetric_name: The name of the symmetric algorithm to use. """
    logger.info("Using cryptosystems: PKC: %s, Symmetric: %s" % \
                (pkc_name, symmetric_name))

    self.__public_context = self.__public_contexts[pkc_name]
    self.__private_context = self.__private_contexts[pkc_name]
    self.__symmetric_context = self.__symmetric_contexts[symmetric_name]

  def get_symmetric(self):
    """ Gets the symmetric cipher that we have currently selected.
    Returns:
      The selected symmetric context, or None if none has been selected. """
    return self.__symmetric_context

  def get_pkc(self):
    """ Gets the PKC that we have currently selected.
    Returns:
      The public context and the private context, or None if none have been
      selected. """
    return self.__public_context, self.__private_context

  def get_supported_symmetric(self):
    """
    Returns:
      The names of all supported symmetric ciphers. """
    return list(self.__symmetric_contexts.keys())

  def get_supported_pkcs(self):
    """
    Returns:
      The names of all supported PKCs. """
    return list(self.__public_contexts.keys())

  def set_mac_keys(self, key):
    """ Convenience function to set the MAC key for all algorithms.
    Args:
      key: The key to set. """
    def set_for_type(context_dict):
      """ Sets the MAC keys in a specific type of context.
      Args:
        context_dict: Context dictionary. """
      for _, context in context_dict.items():
        context.set_mac_key(key)

    set_for_type(self.__private_contexts)
    set_for_type(self.__public_contexts)
    set_for_type(self.__symmetric_contexts)
