from bitstring import BitArray
import socket

def DES(plaintext,key,mode):
    #calls the Initial Permutation
    IP = Inperm(plaintext)
    
    #Splits the plaintext into halves
    L0 = IP[4:]
    R0 = IP[:4]
    
    #Generates K1 and K2 from the key
    PKeys = PermKeys(key)
    K1 = PKeys[0]
    K2 = PKeys[1]
    
    #Round one 
    L1 = R0
    R1 = L0.copy()
    if mode == 0:
        R1 ^= F(R0,K1)
    else:
        R1 ^= F(R0,K2)
    #Round two
    L2 = R1
    R2 = L1 
    if mode == 0:
        R2 ^= F(R1,K2)
    else:
        R2 ^= F(R1,K1)
    
    #Returns the inverted IP of the two halves
    return InvIP(L2,R2)
    

def PermKeys(key):
    #P10: Permutation of 10-bit
    bin_map = [2,4,1,6,3,9,0,8,7,5]
    x = str(key.bin)
    P10 = BitArray('0b'+''.join(x[i] for i in bin_map))    
    
    #split into halves and shift
    L = P10[5:]
    L.rol(1)
    R = P10[:5]
    R.rol(1)
    
    #Creating K1
    K1 = EightPerm(L,R)
    
    #shifting again
    L.rol(1)
    R.rol(1)
    
    #creating K2
    K2 = EightPerm(L,R)
    return (K1,K2)


def F(text,key):
    #creates the SBoxes
    S0 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
    S1 = [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]
    
    #Expansion/Permutation of 4 bit
    bin_map = [3,0,1,2,1,2,3,0]
    bin4 = str(text.bin)
    B8 = BitArray('0b'+''.join(bin4[i] for i in bin_map),2)    
    
    #Xor with the key
    B8 ^= key
    
    #SPlits into 2 4-bits 
    L = B8[4:]
    R = B8[:4]   
    
    outer = [0,3]
    inner = [1,2]
    
    #Leftside through S0
    TmpL = str(L.bin)
    Lcol = int(''.join(TmpL[i] for i in inner),2)    
    Lrow = int(''.join(TmpL[i] for i in outer),2)
    L = BitArray(uint = S0[Lrow][Lcol],length =2)
    
    #Rightside through S1
    TmpR = str(R.bin)
    Rcol = int(''.join(TmpR[i] for i in inner),2)    
    Rrow = int(''.join(TmpR[i] for i in outer),2)
    R = BitArray(uint = S1[Rrow][Rcol],length =2)    
    
    #combine L and R
    combine = BitArray('0b'+str(L.bin)+str(R.bin))
    
    #Last Permutation in F function
    bmap = [1,3,2,0]
    b4 = str(combine.bin)
    return BitArray('0b'+''.join(b4[i] for i in bmap))    

#Initial Permutation Function
#replaces the bits to the mapping (2,6,3,1,4,8,5,7)
def Inperm(ptext):
    bin_map = [1,5,2,0,3,7,4,6]
    x = str(ptext.bin)
    return BitArray('0b'+''.join(x[i] for i in bin_map))

#Inverse Initial Permutation
def InvIP(L,R):
    B8 = str(BitArray('0b'+str(L.bin)+str(R.bin)).bin)
    
    bin_map = [3,0,2,4,6,1,7,5]
    return BitArray('0b'+''.join(B8[i] for i in bin_map))    

#P8: 8 Permutation of 10-bit
def EightPerm(L,R):
    B10 = str(L.bin)+str(R.bin)
    
    bin_map = [5,2,6,3,7,4,9,8]
    return BitArray('0b'+''.join(B10[i] for i in bin_map))


def multDES(ptext,key,mode):
    tmp = True
    maxlen = len(ptext.bin)
    low = 0
    high = 8   
    cipher = BitArray()
    while (tmp):
        if high > maxlen:
            break
        
        plaintext = BitArray('0b'+ptext.bin[low:high])
        if mode == 0: 
            encrypt = DES(plaintext,key,0)
        else:
            encrypt = DES(plaintext,key,1)
        cipher.append(encrypt) 
        low += 8
        high += 8
    return cipher
    

if __name__ == '__main__':
    
    #takes the input for the Plaintext and key
    plaintext = BitArray('0b'+str(input('Enter 8-bit plaintext: ')))
    key = BitArray('0b'+str(input('Enter 10-bit key: ')))
    
    #Encrypts and prints it just to show it works
    encrypt = DES(plaintext,key,0)
    print('Encryption: '+encrypt.bin)
    
    #Prints the decryption to show it works
    print('Decryption: '+DES(encrypt,key,1).bin)