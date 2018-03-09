#!/usr/bin/env python3.4


""" Please make sure to have installed the Bit Vector Library Module from 
    https://pypi.python.org/pypi/BitVector/3.4.7 and running the commands 
    'sudo python setup.py install' """ 


from BitVector import BitVector
from PrimeGenerator import *
import sys
import os
import re

## Value of e
e = 65537

# Euclid's algorithm to compute GCD:
## GCD given in notes
def GCD(x,y):
    if x == y: return x
    if x == 0: return y
    if y == 0: return x
    if (~x & 1):
        if (y &1): return GCD(x >> 1, y)
        else: return GCD(x >> 1, y >> 1) << 1
    if (~y & 1): return GCD(x, y >> 1)
    if (x > y): return GCD( (x-y) >> 1, y)
    return GCD( (y-x) >> 1, x )


# Function to generate keys:
def GenerateKeys(eVAL):
    ## Setup the prime generator
    pg = PrimeGenerator(bits=128, debug=0)
    while(True):
        p = pg.findPrime()
        q = pg.findPrime()
        ## Check p and q are different
        if p == q: continue
        ## Check left two MSB's are 1 (bin command returns 0b appended at front)
        if not (bin(p)[2] and bin(p)[3] and bin(q)[2] and bin(q)[3]): continue
        ## Check that the totients of p and q are co-prime to e
        if (GCD(p-1, eVAL) != 1) or (GCD(q-1, eVAL) !=1): continue
        break
    ## Calculate modulus
    n = p * q
    ## Calculate totient of n
    tn = (p - 1) * (q-1)
    modBV = BitVector(intVal = tn)
    eBV = BitVector(intVal = eVAL)
    ## Calculate multiplicative inverse
    d = eBV.multiplicative_inverse(modBV)
    d = int(d)
    ## Create public and private sets
    public, private = [eVAL, n], [d, n]
    ## Return items
    return public, private, p, q, eVAL


# Function to encrypt the message: 
def encrypt(filename, pubkey):                                  
    encrypted = []
    ## Open the message and get the contents
    message = openFile(filename, True)
    ## Convert to integers
    intM = map(int, message)
    ## Perform the encryption
    for mess in intM:
        encrypted.append(pow(mess, pubkey[0], pubkey[1]))
    return encrypted


# Function to decrypt the message:
def decrypt(filename, private, p, q):
    decrypted = []
    ## Open file and get the contents
    encrypted = openFile(filename, False)

    ## Using the chinese remainder theorem

    ## pCRT = C^d mod p
    ## qCRT = C^d mod q
    pCRT , qCRT = [], []
    for block in encrypted:
        pCRT.append(pow(block, private[0], p))
        qCRT.append(pow(block, private[0], q))

    ## Geting bitvector versions of the p * q values for their multiplicative inverses
    pBV = BitVector(intVal = p)
    qBV = BitVector(intVal = q)

    ## Xp = q * (q^-1 mod p)
    ## Xq = p * (p^-1 mod q)
    pX = q * int(qBV.multiplicative_inverse(pBV))
    qX = p * int(pBV.multiplicative_inverse(qBV))

    ## C^d mod n = (VpXp + VqXq) mod n
    for i in range(len(encrypted)):
        decrypted.append(((pCRT[i] * pX) + (qCRT[i] * qX)) % private[1])
    return decrypted

# Function to read and write the corresponding return values of the keys generated and the generation of private and public keys.
def openFile(file, type):
    ## Get the file length
    flen = os.stat(file).st_size
    bv = BitVector(filename = file)
    ## Read in the blocks, size dependent on encryption or decryption
    if type:
        data_blocks = [bv.read_bits_from_file(128) for i in range((flen/16)+1)]
    else:
        data_blocks = [int(bv.read_bits_from_file(256)) for i in range(flen/32)]
        return data_blocks
    ## New line version of bitvector for appending
    nl = BitVector(textstring = '\n')
    ## Pad the message with new lines
    while(len(data_blocks[-1]) < 128): data_blocks[-1] = data_blocks[-1] + nl
    ## Prepend the data block with 128 zeroes to make it a 256 bit block
    for block in data_blocks: block.pad_from_left(128)
    return data_blocks

## Type = True for encrypt, false for decrypt | Mode = True for text, false for hex
def writeFile(data_block, filename, type, mode):
    ## Open the output file
    out = open(filename, 'wa')
    ## Depending if we're encrypting or decrypting for the size of byte to write
    ## 256 - Encrypt, 128 - Decrypt
    for data in data_block:
        if type:
            bv = BitVector(intVal = data, size = 256)
        else:
            bv = BitVector(intVal = data, size = 128)
        if mode:
            out.write(bv.get_text_from_bitvector())
        else:
            out.write(bv.get_hex_string_from_bitvector())


def main():
    if sys.argv[1] == '-e':
        public, private, p, q, eVAL = GenerateKeys(e)
        ## Write the details of the private key to a file
        with open("private.txt", 'w') as f :
            f.write("d="+str(private[0])+"\n")
            f.write("n="+str(p*q)+"\n")
            f.write("p="+str(p)+"\n")
            f.write("q="+str(q)+"\n")
        ## Write the details of the public key to a file
        with open("public.txt", 'w') as f:
            f.write("e="+str(e)+"\n")
            f.write("n="+str(p*q)+"\n")
        ## Get the encrypted data
        encrypted = encrypt(sys.argv[2], public)
        ## Write the file
        writeFile(encrypted, sys.argv[3], True, True)
        # writeFile(encrypted, "HEX" + sys.argv[3], True, False)
    elif sys.argv[1] == '-d':
        ## Open the private key file to get the private key information
        with open("private.txt", 'r') as f:
            lines = f.read()
        ## Use regex to parse the edata
        private = re.search(r"d=(\d+).*?n=(\d+).*?p=(\d+).*?q=(\d+)", lines, re.DOTALL)
        ## Seperate the regex groups
        d, n, p, q = int(private.group(1)), int(private.group(2)), int(private.group(3)), int(private.group(4))
        ## Setup the private key as a list
        private = [d, n]
        ## Get the decrypted information
        decrypted = decrypt(sys.argv[2], private, p, q)
        ## Write the file out
        writeFile(decrypted, sys.argv[3], False, True)
        # writeFile(decrypted, "HEX"+sys.argv[3], False, False)
        pass


if __name__ == "__main__":
    ## Check the number of arguments
    if len(sys.argv) != 4:
        print("Usage: \n\tEncrypt: ./hw_03.py -e message.txt output.txt\n\tDecrypt: ./hw_03.py -d output.txt decrypted.txt")
        sys.exit(1)
    ## Check the arguments are for encryption or decryption
    if sys.argv[1] != '-e' and sys.argv[1] != '-d':
        print("Usage: \n\tEncrypt: ./hw_03.py -e message.txt output.txt\n\tDecrypt: ./hw_03.py -d output.txt decrypted.txt")
        sys.exit(2)
    ## Check of the input file exists and is readable
    if os.path.isfile(sys.argv[2]) and os.access(sys.argv[2], os.R_OK):
        print("Input file (%s) found and readable. .Outputting to: %s\nProcess starting..." % (sys.argv[2], sys.argv[3]))
        main()
    else:
        print("The file %s cannot be read." % sys.argv[2])
        sys.exit(3)
