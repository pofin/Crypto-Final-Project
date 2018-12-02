class Mac:
  """ Generic interface for all MAC algorithms. """

  @classmethod
  def get_name(self):
    """
    Returns:
      A unique name for this MAC algorithm. """
    raise NotImplementedError("get_name() must be implemented by subclass.")

  def get_length(self):
    """
    Returns:
      The length in characters of the MAC produced by this instance. """
    raise NotImplementedError("get_length() must be implemented by subclass.")

  def generate(self, data):
    """ Generates a new MAC.
    Args:
      data: The message to generate the MAC for.
    Returns:
      The generated MAC, as a string. """
    raise NotImplementedError("generate() must be implemented by subclass.")

  def set_key(self, key):
    """ Sets a new key to use for the MAC.
    Args:
      key: The new key to set. """
    raise NotImplementedError("set_key() must be implemented by subclass.")
