from bitstring import BitArray
from SHA1 import *


def HMAC(K,m):
    key = BitArray(K)
    mess = BitArray(m)
    
    if (len(key.bin) > 512):
        key = BitArray(SHA1(key))
    
    if (len(key.bin) < 512):
        temp = BitArray('0b'+'0'*(512-len(key.bin)))
        key.append(temp)
    
    opad = BitArray('0x5c')
    opad *= 64
    o_key_pad = key.copy()
    o_key_pad ^= opad
    
    ipad = BitArray('0x36')
    ipad *= 64
    i_key_pad = key.copy()
    i_key_pad ^= ipad    

    result = i_key_pad.copy()
    result.append(mess)
    result = BitArray(SHA1(result))
    temp = o_key_pad.copy()
    temp.append(result)
    
    return SHA1(temp)
    

if __name__ == '__main__':
    k = 17867656632
    m = 182347678326476327486327864327864328372643278643287
    print(HMAC(hex(k),hex(m)))