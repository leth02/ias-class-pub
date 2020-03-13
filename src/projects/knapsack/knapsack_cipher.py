#!/usr/bin/env python3
"""Merkle–Hellman Knapsack cipher"""

import math
import pathlib
import random

BLOCK_SIZE = 64

def gcd(a ,b):
    if a == 0:
        return b
    else:
        return gcd(b % a, a)

def generate_sik(size: int = BLOCK_SIZE) -> tuple:
    """Generate a superincreasing knapsack of the specified size"""
    lst = []
    sum = 0
    for i in range(size):
        val = random.randrange(sum+1, sum+10)
        lst.append(val)
        sum += val
    
    return tuple(lst)
        
    #raise NotImplementedError


def calculate_n(sik: tuple) -> int:
    """Calculate N value
    N is the smallest number, greater than the sum of values in the knapsack
    """
    sum = 0
    for i in sik:
        sum += i
    
    return sum+1

    #raise NotImplementedError


def calculate_m(sik: tuple, n: int) -> int:
    """Calculate M value
    M is the largest number in the range [1, N) that is co-prime of N
    """
    
    for i in range(n-1, 0, -1):
        if gcd(i, n) == 1:
            return i
        
    #raise NotImplementedError
    
def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def calculate_inverse(sik: tuple, n: int = None, m: int = None) -> int:
    """Calculate inverse modulo"""
    # n = 491, m = 41
    if n == None:
        return sum(sik)
    
    n0 = n 
    y = 0
    x = 1
  
    if (n == 1) : 
        return 0
  
    while (m > 1) : 
  
        # q is quotient 
        q = m // n 
  
        t = n
  
        # m is remainder now, process 
        # same as Euclid's algo 
        n = m % n 
        m = t 
        t = y 
  
        # Update x and y 
        y = x - q * y 
        x = t 
  
  
    # Make x positive 
    if (x < 0) : 
        x = x + n0 
  
    return x 


def generate_gk(sik: tuple, n: int = None, m: int = None) -> tuple:
    """Generate a general knapsack from the provided superincreasing knapsack"""
    if n == None:
        n = calculate_n(sik)
        m = calculate_m(sik, n)
    
    #for i in range(len(sik)):
        #sik[i] = sik[i]*m%n
    
    return tuple(sik[i]*m%n for i in range(len(sik)))


def encrypt(plaintext: str, gk: tuple, block: int = BLOCK_SIZE) -> list:
    """Encrypt a message"""
    plaintext_l = len(plaintext)
    
    binary_val = ""
    
    for i in range(plaintext_l):
        print(plaintext[i])
        binary_val += format(ord(plaintext[i]), 'b').zfill(8)
    
    
    result = 0
    
    gk_idx = len(gk) - 1
    bi_idx = len(binary_val) - 1
    print(gk)
    print(gk_idx, bi_idx)
    while gk_idx >=0 and bi_idx >= 0:
        
        if binary_val[bi_idx] == "1":
            result += gk[gk_idx]
        gk_idx -= 1
        bi_idx -= 1
        
            
    return [result]

def decrypt(
    ciphertext: list, sik: tuple, n: int = None, m: int = None, block: int = BLOCK_SIZE,
) -> str:
    """Decrypt a single block"""
    
    decimal_val = ciphertext[0] * calculate_inverse(sik, n, m) % n
    print(decimal_val)
    
    l = len(sik) - 1
    
    result = ""
    while l >= 0 and decimal_val > 0:
        if decimal_val >= sik[l]:
            result = "1" + result
            decimal_val -= sik[l]
        else:
            result = "0" + result
        l -=1
    
    print(result)
    result = int(result, 2)
    print(result)
    result = chr(result)
    print(result)
    return result
    
    
    


def main():
    """
    Main function
    Use your own values to check that functions work as expected
    You still need to rely on tests for proper verification
    """
    print("Hellman-Merkle example")


if __name__ == "__main__":
    main()
