#!/usr/bin/env python3
# encoding: UTF-8

from socket import socket, gethostname, AF_INET, SOCK_STREAM
from typing import Tuple, Dict
from diffiehellman.diffiehellman import DiffieHellman

HOST = gethostname()
PORT = 4600



SUPPORTED_CIPHERS = {"AES": [128, 192, 256], "Blowfish": [112, 224, 448], "DES": [56]}

def generate_cipher_proposal(supported: dict) -> str:
    """Generate a cipher proposal message
    
    :param supported: cryptosystems supported by the client
    :return: proposal as a string
    """
    proposed_ciphers = "ProposedCiphers:"
    for key in supported:
        proposed_ciphers += key + ":" + str(supported[key]) + ","
    
    proposed_ciphers = proposed_ciphers[:-1]

    return proposed_ciphers


def parse_cipher_selection(msg: str) -> Tuple[str, int]:
    """Parse server's response
    
    :param msg: server's message with the selected cryptosystem
    :return: (cipher_name, key_size) tuple extracted from the message
    """
    lst = msg.split(":")
    return (lst[1], lst[2])


def generate_dhm_request(public_key: int) -> str:
    """Generate DHM key exchange request

    :param: client's DHM public key
    :return: string according to the specification
    """
    return "DHMKE:" + str(public_key)


def parse_dhm_response(msg: str) -> int:
    """Parse server's DHM key exchange request
    
    :param msg: server's DHMKE message
    :return: number in the server's message
    """
    result = msg.split(":")
    return int(result[1])


def get_key_and_iv(
    shared_key: str, cipher_name: str, key_size: int
) -> Tuple[object, bytes, bytes]:
    """Get key and IV from the generated shared secret key

    :param shared_key: shared key as computed by `diffiehellman`
    :param cipher_name: negotiated cipher's name
    :param key_size: negotiated key size
    :return: (cipher, key, IV) tuple
    cipher_name must be mapped to a Crypto.Cipher object
    `key` is the *first* `key_size` bytes of the `shared_key`
    DES key must be padded to 64 bits with 0
    Length `ivlen` of IV depends on a cipher
    `iv` is the *last* `ivlen` bytes of the shared key
    Both key and IV must be returned as bytes
    """
    raise NotImplementedError


def add_padding(message: str) -> str:
    """Add padding (0x0) to the message to make its length a multiple of 16
    
    :param message: message to pad
    :return: padded message
    """
    raise NotImplementedError


def encrypt_message(message: str, crypto: object, hashing: object) -> Tuple[bytes, str]:
    """
    Encrypt the message

    :param message: plaintext to encrypt
    :param crypto: chosen cipher, must be initialized in the `main`
    :param hashing: hashing object, must be initialized in the `main`
    :return: (ciphertext, hmac) tuple

    1. Pad the message, if necessary
    2. Encrypt using cipher `crypto`
    3. Compute HMAC using `hashing`
    """
    raise NotImplementedError


def main():
    """Main event loop

    See vpn.md for details
    """
    client_sckt = socket(AF_INET, SOCK_STREAM)
    client_sckt.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    print("Negotiating the cipher")
    msg_out = generate_cipher_proposal(SUPPORTED_CIPHERS)
    client_sckt.send(msg_out.encode())
    msg_in = client_sckt.recv(4096).decode("utf-8")
    msg_in = parse_cipher_selection(msg_in)
    cipher_name = msg_in[0]
    key_size = msg_in[1]
    # Follow the description
    print(f"We are going to use {cipher_name}{key_size}")

    print("Negotiating the key")
    # Follow the description
    client_diffiehellman = DiffieHellman(key_length=key_size)
    client_diffiehellman.generate_public_key()

    dhm_out = client_diffiehellman.public_key
    client_sckt.send(generate_dhm_request(dhm_out).encode())

    dhm_in = client_sckt.recv(4096)
    client_diffiehellman.generate_shared_secret(parse_dhm_reponse(dhm_in))

    

    print("The key has been established")

    print("Initializing cryptosystem")
    # Follow the description
    print("All systems ready")

    while True:
        msg_out = input("Enter message: ")
        if msg_out == "\\quit":
            client_sckt.close()
            break
        client_sckt.send(msg_out.encode())
        msg_in = client_sckt.recv(4096)
        print(msg_in.decode("utf-8"))


if __name__ == "__main__":
    main()
