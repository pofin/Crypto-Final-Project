# Cryptography I Final project

## Tasks

### SSL/SSH Protocol Implementation
#### In Progress
Daniel
### Goldwasser Micali
#### Not Started

### Blum Goldwasser
#### Finished (?)

### RSA
#### Semantically Secure In Progress
Jacob

### RC4
#### Finished
Jacob

### DES
#### Not Started

### SHA-1
#### Not Started
Nolan

### HMAC
#### Not Started
Nolan

## RC4
RC4 is a symmetric cryptosystem, that works by taking a fixed size key, and uses it to generate a keystream that is used in a similar manner as a one time pad. The key stream is continuously generated up to the length of the message to be sent. It is then XORed with the message to create the encrypted text. The cryptosystem is implemented as a class in the file [RC4.py](final/crypto/RC4.py).

### Instantiation
In order for the cryptosystem to be used, an object must be created, specifying a key size as the argument.
```
myRC4 = RC4(56)
```

This example creates an RC4 object that uses 56-bit keys. Once the object is created, in order to be used, it needs a key. There are a number of methods that can be used. It can generate a key, or be assigned a key from an external source.

### gen_key()
This function automatically generates and stores a key of appropriate length, stored as a bitarray. The key is returned by the function in the form of a string.
```
key = myRC4.gen_key()
```
The generated is stored as a member variable within the RC4 object.

### get_key()
This function allows for easy retrieval of an already generated or set key.
```
new_key = myRC4.get_key()
```
The value returned is a string.

### set_key()
This function sets the key of an RC4 object, taking a string as an argument.
```
myRC4.set_key("a8@j2f~")
```
This function also resets the key length.

### get_name()
This function returns the unique id for the cryptosystem: "RC4".

### encrypt()
This function takes a message as an argument and encrypts it using an already stored key. The argument is a string, and it returns the encrypted value as a string.
```
encrypted_message = myRC4.encrypt("Message")
```
The encryption function works in two main steps. First, it uses the key stored to generate a keystream. Then, byte by byte it XORs the message with the next part of the keystream. The keystream is implemented as a list with 256 items, where each item is a byte of information. The list starts as the values each equal to their index. The keystream is initialized, using the key. The algorithm below, with the key (key) and keystream (s).
```
j = 0
for i from 0 to 256:
    j = (j + s[i] + key[i mod key length]) mod 256
    swap s[i] and s[j]
```
Next, the message is encrypted byte by byte. As each byte is encrypted, the keystream is modified for the next byte to be encrypted. The encryption works using the algorithm below, once again using the keystream (s).
```
i = 0
j = 0
for byte in message:
    i = i + 1 mod 256
    j = j + s[i] mod 256
    swap s[i] and s[j]
    byte_key = s[s[i] + s[j] mod 256]
    encrypted_byte = byte XOR byte_key
```
Each encrypted byte is converted appended onto one another, until the whole message is encrypted, which is then returned as a string.

### decrypt()
The encryption function takes an encrypted message, in the form of a string, as an argument. The message is decrypted and returned as a string.
```
decrypted_message = myRC4.decrypt(encrypted_message)
```
Since the encryption is done using XORs, the decryption function works the same way as the encryption. The keystream is initialized the same way as in the encryption function, and then the message is decrypted byte by byte modifying the keystream in the same fashion as in the encryption function.

## RSA
RSA is a public key cryptosystem, that works using basic modular math with large numbers. The cryptosystem has a public key, consisting of an encryption value and a modular base, and a private key, the decryption value. The cryptosystem is implemented as a class in the file [RSA.py](final/crypto/RSA.py).

### Instantiation
In order for the cryptosystem to be used, an object must be created, specifying a key size as the argument.
```
myRSA = RSA(128)
```

This example creates an RSA object that uses 128-bit keys. Once the object is initialized, it needs a set of keys in order to be used. This can be done by generating a set of keys, or by setting them from an external source.

### gen_key_pair()
This function generates a pair of keys for the cryptosystem to use, and returns them as a pair, with the public key being a pair of integers representing the encryption value and the modular base, and the private key being an integer representing the decryption value.
```
keys = myRSA.gen_key_pair()
```
 The generation of the key pair begins with the generation of two large primes. In order to create a random prime, the program uses the ```secrets``` library to generate a random number with half as many bits plus one as the keysize for the RSA object. Then, the program performs the Miller Rabin primality test on the number, using an accuracy value of 10000. If the number is determined to be composite, it is added with two, and tested again until it tests as prime. Once the two primes are generated, p and q, the modular base is calculated as n = p*q. Next, the public key (e) is generated by creating a random number with the number of bits as the keysize. Next the Euler function is calculated on n, as (p-1)*(q-1). Then the inverse of the private key is calculated with respect to the result of the Euler function. This value is the private key (d). If the public key is not invertible, the process is restarted with new p and q values. The keys are stored as member variables and returned.

### get_key_pair()
This function returns the stored keys as a list, in the form (int,int), int, with the public key being a pair of integers representing the encryption value and the modular base, and the private key being an integer representing the decryption value.
```
keys = myRSA.get_key_pair()
```

### set_key_pair()
This function sets the keys for the RSA object, taking in as arguments the public key, as a list of two integers representing the encryption value and the modular base, and the private key as an integer.
```
myRSA.set_key_pair([111405670540845042695715069191615509637, 231038902772913249059615478169528941503],30427868915927038427378379900132143189)
```

### copy_with_public_key()
This function returns a copy of the RSA object with the public key only.
```
myRSACopy = myRSA.copy_with_public_key()
```

### get_name()
This function returns the unique id for the cryptosystem: "RSA".

### encrypt_public()
This function encrypts the message passed as an argument using the public key assigned to this RSA object. The message is passed as a string, and the returned encrypted message is a string as well.
```
encrypted_message = myRSA.encrypt_public("Message")
```
The function works by converting the message to the equivalent integer value, making sure that it is small enough. Then the encrypted message is determined by calculating message ^ e mod n. This integer value is then converted to the string equivalent.

### encrypt_private()
This function encrypts the message passed as an argument in the same way as the other encryption function. This time using the private key instead of the public key. This allows an RSA object to be used for message signing if needed.
```
encrypted_message2 = myRSA.encrypt_private("Message")
```

### decrypt_private()
This function decrypts an encrypted message using the private key. It takes a string as an argument, converts it to an integer, and exponentiates it with the private key mod n. This will decrypt a message that has been encrypted using the public key.
```
decrypted_message = myRSA.decrypt_private(encrypted_message)
```

### decrypt_public()
This function decrypts an encrypted message using the public key. It takes a string as an argument, converts it to an integer, and exponentiates it with the public key mod n. This will decrypt a message that has been encrypted using the private key, allowing for the authentication of a signed message.
```
decrypted_message2 = myRSA.decrypt_private(encrypted_message2)
```

## SSRSA
This cryptosystem is a Semantically Secure version of RSA. It inherits most of the functions from the base RSA class, and overwrites the encryption and decryption functions.

### get_name()
This function returns the unique id for the cryptosystem: "SSRSA".

### encrypt_public()
This function encrypts the message passed as an argument using the public key assigned to this RSA object. The message is passed as a string, and the returned encrypted message is a list (int, string).
```
encrypted_message = myRSA.encrypt_public("Message")
```
The function works by generating a random number using the ```secrets``` module. Then the random number is hashed using the SHA1 implementation in [SHA1.py](final/crypto/SHA1.py). The message is split up to chunks of the same size as the hash result, each of which is XORed with the hash result from the random number. The randomness ensures that the encryption is semantically secure. The random value is encrypted using the basic RSA encryption function, with the public key. The returned value is a list with the first value being the encrypted random integer, and the second variable being the encrypted message as a string.

### encrypt_private()
This function encrypts the message passed as an argument in the same way as the other encryption function. This time using the private key instead of the public key. This allows an RSA object to be used for message signing if needed.
```
encrypted_message2 = myRSA.encrypt_private("Message")
```

### decrypt_private()
This function decrypts an encrypted message using the private key. It takes a list with an integer and a string as an argument. First it decrypts the random number using the basic RSA decryption function, and then computes the SHA1 hash result. Then XORs each chunk of the encrypted message. This will decrypt a message that has been encrypted using the public key.
```
decrypted_message = myRSA.decrypt_private(encrypted_message)
```

### decrypt_public()
This function decrypts an encrypted message using the public key, the same way as the private key decryption function. This will decrypt a message that has been encrypted using the private key, allowing for the authentication of a signed message.
```
decrypted_message2 = myRSA.decrypt_private(encrypted_message2)
```

## Authors

* **Jacob Doskocil**
* **Daniel Petti**
* **Nolan Pofi**
* **John Angel**
