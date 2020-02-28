#!/usr/bin/env python3
# encoding: UTF-8
"""A5/1 cipher"""
from hashlib import sha256


def populate_registers(init_keyword: str) -> tuple:
    """Populate registers

    init_keyword -- inital secret word that will be used to populate registers X, Y, and Z
    
    return registers X, Y, Z as a tuple
    """
    xyz = ""
    for char in init_keyword:
        xyz += bin(ord(char))[2:].zfill(8)
        
    
    if len(xyz) < 64:
        xyz = xyz.ljust(64,"0")
    
    x = xyz[:19]
    y = xyz[19:41]
    z = xyz[41:]
    
    print(len(z))
    return (x , y, z)


def majority(x8_bit: str, y10_bit: str, z10_bit: str) -> str:
    """Return the majority bit
    
    x8_bit -- 9th bit from the X register
    y10_bit -- 11th bit from the Y register
    z10_bit -- 11th bit from the Z register

    return the value of the majority bit
    """
    if x8_bit == "1":
        if y10_bit == "1":
            return "1"
        else:
            if z10_bit == "1":
                return "1"
            else:
                return "0"
    else:
        if y10_bit == "1":
            if z10_bit == "0":
                return "0"
            else:
                return "1"
        else:
            return "0"
        
def cal_XOR(a, b):
    if a != b:
        return "1"
    else:
        return "0"

def step_x(register: str) -> str:
    """Stepping register X
    
    register -- X register
    
    return new value of the X register
    """
    x13_bit = register[13]
    x16_bit = register[16]
    x17_bit = register[17]
    x18_bit = register[18]
    
    t = cal_XOR(cal_XOR(cal_XOR(x13_bit, x16_bit), x17_bit), x18_bit)
    
    register = t + register[:-1]
    
    return register


def step_y(register: str) -> str:
    """Stepping register Y
    
    register -- Y register
    
    return new value of the Y register
    """
    y20_bit = register[20]
    y21_bit = register[21]
    
    t = cal_XOR(y20_bit, y21_bit)
    
    register = t + register[:-1]
    
    return register

def step_z(register: str) -> str:
    """Stepping register Z
    
    register -- Z register
    
    return new value of the Z register
    """
    z7_bit = register[7]
    z20_bit = register[20]
    z21_bit = register[21]
    z22_bit = register[22]
    
    t = cal_XOR(cal_XOR(cal_XOR(z7_bit, z20_bit), z21_bit), z22_bit)
    register = t + register[:-1]
    return register


def generate_bit(x: str, y: str, z: str) -> int:
    """Generate a keystream bit
    
    x -- X register
    y -- Y register
    z -- Z register

    return a single keystream bit
    """
    return (int(cal_XOR(cal_XOR(x[18], y[21]), z[22])))


def generate_keystream(plaintext: str, x: str, y: str, z: str) -> str:
    """Generate stream of bits to match length of plaintext
    
    plaintext -- plaintext to be encrypted
    x -- X register
    y -- Y register
    z -- Z register

    return keystream
    """
    result = ""
    
    plaintext_binary = ""
    for char in plaintext:
        plaintext_binary += bin(ord(char))[2:].zfill(8)
    
    #print("binary", plaintext_binary)

    for i in range(0, len(plaintext_binary)):
        maj = majority(x[8], y[10], z[10])
        if x[8] == maj:
            x = step_x(x)
        if y[10] == maj:
            y = step_y(y)
        if z[10] == maj:
            z = step_z(z)

        bit = generate_bit(x, y, z)
        
        result += str(bit)
        #print(result)
    return result


def encrypt(plaintext: str, keystream: str) -> str:
    """Encrypt plaintext using A5/1
    
    plaintext -- plaintext to be encrypted
    keystream -- keystream

    return ciphertext
    """
    result = ""
    
    plaintext_binary = ""
    for char in plaintext:
        plaintext_binary += bin(ord(char))[2:].zfill(8)    
    
    for i in range(0, len(plaintext_binary)):
        result += cal_XOR(plaintext_binary[i], keystream[i])
    
    return result


def encrypt_file(filename: str, secret: str) -> None:
    """Encrypt a file
    
    filename -- filename to be encrypted
    secret -- secret to initialize registers

    return write the result to filename.secret
    """
    r = open(filename, "r")
    w = open("data/projects/a51/roster.secret", "w")
    
    for line in r:
        x, y, z = populate_registers(secret)
        keystream = generate_keystream(line, x, y, z)
        dcm =  encrypt(line, keystream)
        
        w.write(hex(int(dcm, 2)) + '\n')

def main():
    """Main function"""

    encrypt_file("data/projects/a51/roster", "martin")
    
    r = sha256(open("data/projects/a51/roster.secret", "rb").read()).hexdigest()
    print(r)
 
    
    
if __name__ == "__main__":
    main()
