from . import mac


class StupidMac(mac.Mac):
  """ This is a MAC that always produces the same results. Only for testing. """

  @classmethod
  def get_name(cls):
    return "StupidMAC"

  def get_length(self):
    return 6

  def generate(self, data):
    return "daniel"
