# Cryptography I Final project

## Using this Code

The code is written in Python 3, and should be fairly easy to run.

### Dependencies

This code depends on the bitarray and bitstring Python packages.

### Testing the Communication

A test client and server can be started on the same machine. To start the
server:

```
~$ python3 test_server.py 1337
```

The first argument here is the port number to listen on.

Now, start the test client:

```
~$ python3 test_client.py 127.0.0.1 1337
```

The first argument is the host to connect to, and the second is the port to
connect on.

The client should perform the handshake with the server, and then provide a
message prompt. Type anything here, and hit enter. You should see a message from
the server displaying what you just typed.

### Cryptosystem Configuration

The cryptosystems are configured using specialized configuration files under the
config directory. Both the client and the server take several options allowing
the configuration files to be specified. See ```test_client.py -h``` and
```test_server.py -h``` for more information.

## Write-ups

### Daniel

My write up is available
[here.](https://github.com/pofin/Crypto-Final-Project/blob/master/docs/Crypto_White_Hat_Write_Up.pdf)

### Nolan

Here is my write up
[here.](https://github.com/pofin/Crypto-Final-Project/blob/master/docs/write_up_Nolan_Pofi.pdf)

### Jacob
My write up is available [here.](https://github.com/pofin/Crypto-Final-Project/blob/master/docs/Jacob_Doskocil_Documentation.md)


## Authors

* **Jacob Doskocil**
* **Daniel Petti**
* **Nolan Pofi**
* **John Angel**
