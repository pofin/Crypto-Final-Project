from bitstring import BitArray
from .SHA1 import *
from . import mac

def Hmac(K,m):
    """ Computes the HMAC.
    Args:
      K: String representation of the key.
      m: String representation of the message.
    Returns:
      The computed HMAC. """
    key = BitArray(K.encode("latin-1"))
    mess = BitArray(m.encode("latin-1"))

    #shortens key if its larger than the block size of SHA1
    if (len(key.bin) > 512):
        key = BitArray(SHA1(key))

    #pads the key to the size of a block in SHA1
    if (len(key.bin) < 512):
        temp = BitArray('0b'+'0'*(512-len(key.bin)))
        key.append(temp)

    #the outer pad
    opad = BitArray('0x5c')
    opad *= 64
    o_key_pad = key.copy()
    o_key_pad ^= opad

    #the inner pad
    ipad = BitArray('0x36')
    ipad *= 64
    i_key_pad = key.copy()
    i_key_pad ^= ipad

    #pads the message with two hashes
    result = i_key_pad.copy()
    result.append(mess)
    result = BitArray(SHA1(result))
    temp = o_key_pad.copy()
    temp.append(result)

    return SHA1(temp).bytes.decode("latin-1")


class HMAC(mac.Mac):

    def __init__(self,k):
        self.key = k

    @classmethod
    def get_name(cls):
        return "HMAC"

    def get_length(self):
        return 20

    def generate(self, data):
        return Hmac(self.key, data)


if __name__ == '__main__':
    k = 17867656632
    m = 182347678326476327486327864327864328372643278643287
    print(HMAC(hex(k),hex(m)))
