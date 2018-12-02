from bitstring import BitArray

#Implements SHA-1 hash function
#assumes m is a hex string
#returns a 160-bit hex string
def SHA1(m):
    #initialising variables for use in Hash
    mt = BitArray(m)
    h0 = BitArray('0x67452301')
    h1 = BitArray('0xEFCDAB89')
    h2 = BitArray('0x98BADCFE')
    h3 = BitArray('0x10325476')
    h4 = BitArray('0xC3D2E1F0')
    
    #processing message so that it fits Hash Format
    m1 = len(BitArray(m).bin)
    m2 = m1
    if m1%8 == 0:
        m2 += 1
        mt.append(BitArray('0b1'))
    
    #more processing by adding a pad so message is divisible into 512 bit chunks
    temp_len = m2%512
    pad = 0
    if temp_len < 448:
        pad = 448-temp_len
    else:
        pad = (512-temp_len) + 448
    
    padding = BitArray('0b'+'0'*pad)
    padding.append(BitArray(uint=m1,length=64))   
    mt.append(padding)
    
    pad_len = len(mt.bin)
    
    Imin = 0
    Imax = 512
    #breaks message into 512 bit chunks and works on each one
    while Imax <= pad_len:
        
        block = BitArray('0b'+mt.bin[Imin:Imax])
        
        #splits 512 bit chunk into 16, 32 bit chunks
        w = [0]*80
        low = 0
        up = 16
        for i in range(16):
            w[i] = BitArray('0b'+block.bin[low:up])
            low +=16
            up += 16
        
        #then expands to 80 32 bit chunks
        for i in range(16,80):
            temp_BA = w[i-3].copy()
            temp_BA ^= w[i-8]
            temp_BA ^= w[i-14]
            temp_BA ^= w[i-16]
            temp_BA.rol(1) 
            w[i] = temp_BA.copy()
       
        #initialize hash values for this chunk
        a = h0.copy()
        b = h1.copy()
        c = h2.copy()
        d = h3.copy()
        e = h4.copy()
        
        
        for i in range(40,41):
            #the F function used
            if 0 <= i <20:
                tb = b.copy()
                tb &= c
                ntb = b.copy()
                ntb.invert()
                ntb &= d
                tb |= ntb
                fun = tb.copy()
                k = BitArray('0x5A827999')
            elif 20 <= i <40:
                tb = b.copy()
                tb ^= c
                tb ^= d
                fun = tb.copy()
                k = BitArray('0x6ED9EBA1')
            elif 40 <= i < 60:
                tb = b.copy()
                tb &= c
                ttb = b.copy()
                ttb &= d
                tc = c.copy()
                tc &= d
                tb |= ttb
                tb |= tc
                fun = tb.copy()
                k = BitArray('0x8F1BBCDC')
            elif 60 <= i < 80:
                tb = b.copy()
                tb ^= c
                tb ^= d
                fun = tb.copy()
                k = BitArray('0xCA62C1D6')            
        
            temp = a.copy()
            temp.rol(5)
            temp_val = (temp.uint + fun.uint + e.uint + k.uint + w[i].uint)% 2**32
            temp = BitArray(uint = temp_val,length = 32)
            e = d.copy()
            d = c.copy()
            c = b.copy()
            c.rol(30)
            b = a.copy()
            a = temp.copy()
            
        #updates h0,h1,h2,h3,h4 so as to cause avalanche effect
        tval = (h0.uint + a.uint)% 2**32
        h0 = BitArray(uint = tval,length = 32)        
        tval = (h1.uint + b.uint)% 2**32
        h1 = BitArray(uint = tval,length = 32) 
        tval = (h2.uint + c.uint)% 2**32
        h2 = BitArray(uint = tval,length = 32) 
        tval = (h3.uint + d.uint)% 2**32
        h3 = BitArray(uint = tval,length = 32) 
        tval = (h4.uint + e.uint)% 2**32
        h4 = BitArray(uint = tval,length = 32) 
        
        Imin += 512
        Imax += 512
    
    #combines into 160 bit hash value and returns
    hh = h0.copy()
    hh.append(h1)
    hh.append(h2)
    hh.append(h3)
    hh.append(h4)
    return '0x'+hh.hex



if __name__ == '__main__':
    x = 67812786123786127856785437834271826378612352135662317896389987387934869
    print(SHA1(hex(x)))