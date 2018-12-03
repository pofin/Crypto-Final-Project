from .cryptosystem import Symmetric
from bitarray import *
import secrets

class TripleDES(Symmetric):
    def __init__(self):
        self.keysize = 64
        self.key1 = ""
        self.key2 = ""
        self.key3 = ""

    def encrypt(self, message):
        bitMessage = bitarray()
        message = message + "ENDMESS"
        bitMessage.frombytes(message.encode('latin-1'))

        #Add padding to the end of messages so that the blocks are 64
        if(len(bitMessage)%64 != 0):
            for i in range(64 - (len(bitMessage)%64) ):
                bitMessage.insert(len(bitMessage), 0)

        cipher = blockChainTripleDES(bitMessage, self.key1, self.key2, self.key3, 0)
        return cipher.to01()

    def decrypt(self, message):
        cipher = bitarray(message)
        plaintext = blockChainTripleDES(cipher, self.key1, self.key2, self.key3, 1)
        decoded = plaintext.tobytes().decode('latin-1')
        indexOfEnd = decoded.find("ENDMESS")
        return decoded[:indexOfEnd]

    def gen_key(self):
        """ Generates three 64-bit random key for this cryptosystem.
        Args:
            None.
        Returns:
            None."""

        key1 = bin(secrets.randbits(64))[2:]
        key2 = bin(secrets.randbits(64))[2:]
        key3 = bin(secrets.randbits(64))[2:]

        #Add padding to the front of keys to make sure they are 64 bits
        while(len(key1) < 64):
            key1 = "0"+key1
        while(len(key2) < 64):
            key2 = "0"+key2
        while(len(key3) < 64):
            key3 = "0"+key3

        self.key1 = key1
        self.key2 = key2
        self.key3 = key3

    def set_key(self, newKeysList):
        """ Sets the key to the argument value
        Args:
            newKeysList List[string,string,string]: the new keys to set. """
        self.key1 = newKeysList[0]
        self.key2 = newKeysList[1]
        self.key3 = newKeysList[2]

    def get_key(self):
        """ Get the current gen_key
        Args:
            None.
        Returns:
            List[string,string,string]: Current keys. """
        return self.key1, self.key2, self.key3

    @classmethod
    def get_name(cls):
        """ Returns the unique name for this cryptosystem """
        return "TripleDES"

    @classmethod
    def get_priority(cls):
        """ Returns the priority for this cryptosystem """
        return 1
  

def DES(plaintext,key,mode):
    #calls the Initial Permutation
    IP = Inperm(plaintext)
    
    #Splits the plaintext into halves
    L0 = IP[32:]
    R0 = IP[:32]
    
    #Generates K1 and K2 from the key
    PKeys = PermKeys(key)
    
    #Rounds
    for i in range(16):
        L1 = R0
        R1 = L0.copy()
        if mode == 0:
            R1 ^= F(R0,PKeys[i])
        else:
            R1 ^= F(R0,PKeys[::-1][i])
        R0 = R1
        L0 = L1
        
    
    #Returns the inverted IP of the two halves
    return InvIP(L1,R1)
    

def PermKeys(key):
    bitArrayKey = bitarray(key)
    
    #P56: Permutation of from 64 bit to 56 bit
    bin_map = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3]
    x = bitArrayKey.to01()
    P56 = bitarray(''.join(x[i] for i in bin_map))    
    
    #split into halves and shift
    L = P56[28:]
    R = P56[:28]
    Rol(L,1)
    Rol(R,1)
    
    #Creating K1
    K1 = FourtyEightPerm(L,R)
    
    #shifting again
    Rol(L,1)
    Rol(R,1)
    
    #creating K2
    K2 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K3
    K3 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K4
    K4 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K5
    K5 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K6
    K6 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K7
    K7 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K8
    K8 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,1)
    Rol(R,1)
    
    #creating K9
    K9 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K10
    K10 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K11
    K11 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K12
    K12 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K13
    K13 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K14
    K14 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,2)
    Rol(R,2)
    
    #creating K15
    K15 = FourtyEightPerm(L,R)

    #shifting again
    Rol(L,1)
    Rol(R,1)
    
    #creating K16
    K16 = FourtyEightPerm(L,R)


    
    return (K1,K2,K3,K4,K5,K6,K7,K8,K9,K10,K11,K12,K13,K14,K15,K16)


def F(text,key):
    #creates the SBoxes
    S1 = [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]
    S2 = [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]
    S3 = [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]
    S4 = [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]]
    S5 = [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]]
    S6 = [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]]
    S7 = [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]]
    S8 = [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    
    #Expansion/Permutation of 4 bit
    bin_map = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
    bin32 = text.to01()
    B48 = bitarray(''.join(bin32[i-1] for i in bin_map))
    
    #Xor with the key
    B48 ^= key
    
    #Splits into 8 6-bits 
    Box1 = B48[0:6]
    Box2 = B48[6:12]
    Box3 = B48[12:18]
    Box4 = B48[18:24]
    Box5 = B48[24:30]
    Box6 = B48[30:36]
    Box7 = B48[36:42]
    Box8 = B48[42:48]
    
    outer = [0,5]
    inner = [1,2,3,4]
    
    #Box1 through S1
    TmpBox1 = Box1.to01()
    Box1col = int(''.join(TmpBox1[i] for i in inner),2)    
    Box1row = int(''.join(TmpBox1[i] for i in outer),2)
    Box1Ans = bitarray(fillBinString(bin(S1[Box1row][Box1col])[2:], 4))
    
    #Box2 through S2
    TmpBox2 = Box2.to01()
    Box2col = int(''.join(TmpBox2[i] for i in inner),2)    
    Box2row = int(''.join(TmpBox2[i] for i in outer),2)
    Box2Ans = bitarray(fillBinString(bin(S2[Box2row][Box2col])[2:], 4))

    #Box3 through S3
    TmpBox3 = Box3.to01()
    Box3col = int(''.join(TmpBox3[i] for i in inner),2)    
    Box3row = int(''.join(TmpBox3[i] for i in outer),2)
    Box3Ans = bitarray(fillBinString(bin(S3[Box3row][Box3col])[2:], 4))

    #Box4 through S4
    TmpBox4 = Box4.to01()
    Box4col = int(''.join(TmpBox4[i] for i in inner),2)    
    Box4row = int(''.join(TmpBox4[i] for i in outer),2)
    Box4Ans = bitarray(fillBinString(bin(S4[Box4row][Box4col])[2:], 4))

    #Box5 through S5
    TmpBox5 = Box5.to01()
    Box5col = int(''.join(TmpBox5[i] for i in inner),2)    
    Box5row = int(''.join(TmpBox5[i] for i in outer),2)
    Box5Ans = bitarray(fillBinString(bin(S5[Box5row][Box5col])[2:], 4))

    #Box6 through S6
    TmpBox6 = Box6.to01()
    Box6col = int(''.join(TmpBox6[i] for i in inner),2)    
    Box6row = int(''.join(TmpBox6[i] for i in outer),2)
    Box6Ans = bitarray(fillBinString(bin(S6[Box6row][Box6col])[2:], 4))

    #Box7 through S7
    TmpBox7 = Box7.to01()
    Box7col = int(''.join(TmpBox7[i] for i in inner),2)    
    Box7row = int(''.join(TmpBox7[i] for i in outer),2)
    Box7Ans = bitarray(fillBinString(bin(S7[Box7row][Box7col])[2:], 4))

    #Box8 through S8
    TmpBox8 = Box8.to01()
    Box8col = int(''.join(TmpBox8[i] for i in inner),2)    
    Box8row = int(''.join(TmpBox8[i] for i in outer),2)
    Box8Ans = bitarray(fillBinString(bin(S8[Box8row][Box8col])[2:], 4))
    
    #combine the s boxes results
    combine = bitarray(Box1Ans.to01()+Box2Ans.to01()+Box3Ans.to01()+Box4Ans.to01()+Box5Ans.to01()+Box6Ans.to01()+Box7Ans.to01()+Box8Ans.to01())
    
    #Last Permutation in F function
    bmap = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
    b32 = combine.to01()
    return bitarray(''.join(b32[i-1] for i in bmap))    

#Initial Permutation Function
#replaces the bits to the mapping (2,6,3,1,4,8,5,7)
def Inperm(ptext):
    bin_map = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
    
    x = ptext.to01()
    return bitarray(''.join(x[i-1] for i in bin_map))

#Inverse Initial Permutation
def InvIP(L,R):
    B8 = bitarray(L.to01()+R.to01()).to01()
    
    bin_map = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
    
    return bitarray(''.join(B8[i-1] for i in bin_map))    

#P48: 48 Permutation of 56-bit
def FourtyEightPerm(L,R):
    B56 = L.to01()+R.to01()
    
    bin_map = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,33,53,45,41,49,35,28,31]
    return bitarray(''.join(B56[i] for i in bin_map))

def Rol(bitArr, num):
    for i in range(num):
        bitArr.insert(len(bitArr), bitArr.pop(0))

def fillBinString(string, num):
    answerString = string
    while (len(answerString) < num):
        answerString = "0" + answerString
    return answerString

def blockChainDES(ptext,key,mode):
    tmp = True
    maxlen = len(ptext.to01())
    low = 0
    high = 64  
    cipher = bitarray()
    ciphertext = ""
    while (tmp):
        if high > maxlen:
            break
        
        plaintext = bitarray(ptext.to01()[low:high])
        if mode == 0: 
            encrypt = DES(plaintext,key,0)
        else:
            encrypt = DES(plaintext,key,1)
        
        ciphertext = ciphertext + encrypt.to01()
        low += 64
        high += 64
    return bitarray(ciphertext)

def blockChainTripleDES(ptext,key1,key2,key3,mode):
    tmp = True
    maxlen = len(ptext.to01())
    low = 0
    high = 64  
    cipher = bitarray()
    ciphertext = ""
    while (tmp):
        if high > maxlen:
            break
        
        plaintext = bitarray(ptext.to01()[low:high])
        if mode == 0: 
            encrypt = tripleDES(plaintext,key1,key2,key3,0)
        else:
            encrypt = tripleDES(plaintext,key1,key2,key3,1)
        
        ciphertext = ciphertext + encrypt.to01()
        low += 64
        high += 64
    return bitarray(ciphertext)

def tripleDES(ptext, key1, key2, key3, mode):
    if mode == 0:
        return DES(DES(DES(ptext,key1,0), key2, 1), key3, 0)
    else:
        return DES(DES(DES(ptext,key3,1), key2, 0), key1, 1)
    

if __name__ == '__main__':
    
    #takes the input for the Plaintext and key
    plaintext = bitarray("1000100010001000100010001000100010001000100010001000100010001000")
    key = bitarray("1000110011001001100010001000100010001000100010101000100010001100")
    
    #Encrypts and prints it just to show it works
    encrypt = DES(plaintext,key,0)
    print('Encryption: '+encrypt.to01())
    
    #Prints the decryption to show it works
    print('Decryption: '+DES(encrypt,key,1).to01())
