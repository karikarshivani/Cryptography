# Sample function to convert integers to binary

binary_data = ""

def int_to_binary(num):
    global binary_data
    binary_data += str(num % 2)
    if num >= 1:
        int_to_binary(num // 2)

int_to_binary(42)
print(binary_data)


# _______________________________________________________________________________________________________________________
# ASCII represents text using 7-bit numbers using numbers between 0 and 127
# To convert ASCII numbers to text: chr() | To convert text to ASCII: ord()

ascii_list = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
chars = ""

for num in ascii_list:
    chars += chr(num)

print(chars)

# _______________________________________________________________________________________________________________________
# Hex is commonly used to encode ciphertext instead of ASCII because ciphertext may contain characters that are not printable by ASCII (128 character limit)
# To convert hex into byte string: bytes.fromhex(<hex_string>) | To convert byte string into hex: bytes.hex(<b''>)

hex_string = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
print(bytes.fromhex(hex_string))
converted_string = b"crypto{You_will_be_working_with_hex_strings_a_lot}" # b is for Byte String
bytes.hex(converted_string)


# _______________________________________________________________________________________________________________________
# Base64 is commonly used to convert binary data into ASCII strings of 64 characters and is web safe
# To convert data into base64: base64.b64encode(<data>)

import base64
from operator import xor

hex_string = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
data = bytes.fromhex(hex_string)
print(base64.b64encode(data))


# _______________________________________________________________________________________________________________________
# Cryptosystems (like RSA) perform mathematical operations on numbers. Commonly, characters are converted into ordinals, then hex (alternatively base 10), then concatenated
# To convert characters into these layers of encoding: bytes_to_long(b'<data>') | To convert it back to characters: long_to_bytes(<encoded numbers>)

from Crypto.Util.number import *

print(long_to_bytes(11515195063862318899931685488813747395775516287289682636499965282714637259206269))
bytes_to_long(b'crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}')


# _______________________________________________________________________________________________________________________
# XOR: same = 0 | different = 1. Integers need to be converted from decimal to binary first. Characters need to be converted to unicode
# To XOR values: xor(value1, value2)

from pwn import *

print(xor(b"label", 13))
print("hello")

# FLAG ^ KEY1 ^ KEY3 ^ KEY2

key1hex = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
key1n2 = bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e")

key2hex = xor(key1hex, key1n2)
key2n3 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
key3hex = xor(key2hex, key2n3)

flag_xor_hex = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")
step1 = xor(flag_xor_hex, key1hex)
step2 = xor(step1, key3hex)
step3 = xor(step2, key2hex)

print(step3)

hex_data = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

for ascii in range(0, 17, 4): # range(255) per byte of data
    print(f"Byte {ascii}: {xor(hex_data, ascii)}")

hex_data = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")
print(xor(hex_data, b"crypto{")) # using pattern matching to find common inital characters in key
print(xor(hex_data, b"myXORkey")) # using common characters to decrypt data using the partial key

# _______________________________________________________________________________________________________________________
# Greatest Common Divisor (GCD) is the largest number that can divide two given numbers. The first function below does it the straight-forward but resource-intensive way. The second function follows's Euclidean Algorithm. By finding the difference between the given values, you can come to a common number that is the GCD. Think about them as big leaps.

num1 = 5
num2 = 2

def gcd(a, b):
    for num in range(a if a < b else b, 0, -1):
        if a % num == 0 and b % num == 0:
            return num

print(gcd(num1, num2))

def euclid(a, b):
    while a != b:
        if a > b:
            a = a - b
        else:
            b = b - a
    return a

print(euclid(252, 105))

## Fermat's little theorem | Condition: a must be < p | a is given number and p is prime number (83 here)
# a^p-1 = 1 mod p
print((1 ** 82) % 83)
print((2 ** 82) % 83)
print((3 ** 82) % 83)
# a^p = a mod p
print((4 ** 83) % 83)
print((5 ** 83) % 83)
print((6 ** 83) % 83)
# a^p+1 = (a^2 mod p) mod p
print((7 ** 84) % 83)
print((8 ** 84) % 83)
print((9 ** 84) % 83)

## Quadratic Residues | Finding square root modulo of an integer

print("Quadratic Residues")
# print((11**2)%29)

for a in range(29):
    if (a**2)%29 == 6:
        print(a)

print("Start")

print(base64.b64decode("0JYfyYwAAAAB8A97xMrS9TZtzpDjKkWSuTU5aMjIxMDYwNjEzMDM5ADU2N2IxYjA2LWMzOWMtNDFlNy05NDk1LTE2YWUzYWEzNjYyZQ=="))

for i in range(10):
    print(i, base64.b64decode(b"0JYfyYwAAAAB8A97xMrS9TZtzpDjKkWSuTU5aMjIxMDYwNjEzMDM5ADU2N2IxYjA2LWMzOWMtNDFlNy05NDk1LTE2YWUzYWEzNjYyZQ=="))


# String format notation (Integer (d), Hex (x), Octal (o), Binary (b))

print(f"Hex: {42:#x} | Binary: {42:#b}") # Removing # before format letter will remove prefixes 0x, 0o, or 0b


# Rough work

# 5808 = 32321 - 1(26513)
# 3281 = 5(26513) - 4(32321)
# 2527 = 5(32321) - 6(26513)
# 754 = 11(26513) - 9(32321)
# 265 = 32(32321) - 39(26513)
# 224 = 89(26513) - 73(32321)
# 41 = 105(32321) - 128(26513)
# 19 = 729(26513) - 598(32321)
# 3 = 1301(32321) - 1586(26513)
# 1 = 10245(26513) - 8404(32321)
