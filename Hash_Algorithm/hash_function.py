"""

# Created by Priyanka Wania
# SJSU id: 011874941
# written for Python3

        Implement a very simple hash function. The function creates a 32- bit hash of a file.
        (CMPE 209 - Network Security, Assignment number - 2)
        
        5 steps are required to produce hash. 
        
"""

#!/usr/bin/env python

import sys

from BitVector import *
from glob import *

# declare k

k = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f",
     "e9b5dba58189dbbc", "3956c25bf348b538", "59f111f1b605d019",
     "923f82a4af194f9b", "ab1c5ed5da6d8118", "d807aa98a3030242",
     "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
     "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235",
     "c19bf174cf692694", "e49b69c19ef14ad2", "efbe4786384f25e3",
     "0fc19dc68b8cd5b5", "240ca1cc77ac9c65", "2de92c6f592b0275",
     "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
     "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f",
     "bf597fc7beef0ee4", "c6e00bf33da88fc2", "d5a79147930aa725",
     "06ca6351e003826f", "142929670a0e6e70", "27b70a8546d22ffc",
     "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
     "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6",
     "92722c851482353b", "a2bfe8a14cf10364", "a81a664bbc423001",
     "c24b8b70d0f89791", "c76c51a30654be30", "d192e819d6ef5218",
     "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
     "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99",
     "34b0bcb5e19b48a8", "391c0cb3c5c95a63", "4ed8aa4ae3418acb",
     "5b9cca4f7763e373", "682e6ff3d6b2b8a3", "748f82ee5defb2fc",
     "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
     "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915",
     "c67178f2e372532b", "ca273eceea26619c", "d186b8c721c0c207",
     "eada7dd6cde0eb1e", "f57d4f7fee6ed178", "06f067aa72176fba",
     "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
     "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc",
     "431d67c49c100d4c", "4cc5d4becb3e42b6", "597f299cfc657e2a",
     "5fcb6fab3ad6faec", "6c44198c4a475817"]
	
			
def get_input (input_file):
    with open (input_file, 'r') as MyFile:
        raw_message = MyFile.read()
    message = BitVector(textstring = raw_message)
    llength = len(message)
    message_pp = message + BitVector(intVal = 1)
    zeros = (895 - llength) % 1024
    yo = BitVector(intVal = 0, size = zeros)
    newm = message_pp + yo
    flen = BitVector(intVal = llength, size = 128)
    mess_p_len = newm + flen
    final_list = []
    for i in range (0, len(mess_p_len), 1024):
        temp = mess_p_len[i:i+1024]
        final_list.append(temp)
    return final_list
	
	
def hash (input_file):
    input_data = get_input(input_file)
    #do a,b,c,... and prev_a prev_b ...
    two64 = 2 ** 64
    #get starting registers
    
    a = BitVector(hexstring="6a09e667f3bcc908")
    b = BitVector(hexstring="bb67ae8584caa73b")
    c = BitVector(hexstring="3c6ef372fe94f82b")
    d = BitVector(hexstring="a54ff53a5f1d36f1")
    e = BitVector(hexstring="510e527fade682d1")
    f = BitVector(hexstring="9b05688c2b3e6c1f")
    g = BitVector(hexstring="1f83d9abfb41bd6b")
    h = BitVector(hexstring="5be0cd19137e2179")
	 
    a_prev = int(a) 
    b_prev = int(b) 
    c_prev = int(c) 
    d_prev = int(d) 
    e_prev = int(e) 
    f_prev = int(f) 
    g_prev = int(g)
    h_prev = int(h) 
    
    for chunk in input_data:
        words = [None] * 80
	words[0:16] = [chunk[i:i+64] for i in range(0,1024,64)]
	for i in range (16, 80):
	   words[i] = do_words(words[i-16], words[i-15], words[i-7], words[i-2])
	
	#do the 80 rounds
	for i in range(80):
	
            T1 = (int(h) + int((e & f) ^ (~e & g))) % two64
	    T1 = (T1 + sigmae(e)) % two64
	    T1 = (T1 + int(words[i])) % two64
	    T1 = (T1 + int(BitVector(hexstring = k[i]))) % two64
	    T2 = (sigmaa(a) + int ((a & b) ^ (a & c) ^ (b & c)))% two64
	    h = g.deep_copy()
	    g = f.deep_copy()
	    temp = (int(d) + T1) % two64
	    e = BitVector(intVal = temp, size =64)
	    d = c.deep_copy()
	    c = b.deep_copy()
	    b = a.deep_copy()
	    temp = (T1 + T2) % two64
            a = BitVector(intVal = temp, size =64)
	 
        a_prev = (int(a) + a_prev) % two64 
        b_prev = (int(b) + b_prev) % two64 
        c_prev = (int(c) + c_prev) % two64 
        d_prev = (int(d) + d_prev) % two64 
        e_prev = (int(e) + e_prev) % two64 
        f_prev = (int(f) + f_prev) % two64 
        g_prev = (int(g) + g_prev) % two64 
        h_prev = (int(h) + h_prev) % two64 
	 
        a = BitVector(intVal = a_prev, size = 64)
        b = BitVector(intVal = b_prev, size = 64)
        c = BitVector(intVal = c_prev, size = 64)
        d = BitVector(intVal = d_prev, size = 64)
        e = BitVector(intVal = e_prev, size = 64)
        f = BitVector(intVal = f_prev, size = 64)
        g = BitVector(intVal = g_prev, size = 64)
        h = BitVector(intVal = h_prev, size = 64)
	
	
    final_hash = a + b + c + d + e + f + g + h
    print("done")
    with open ("output.txt", 'w') as MyFile:
        MyFile.write(final_hash.get_hex_string_from_bitvector())
	
	
def do_words(words_16, words_15, words_7, words_2):
    two64 = 2 ** 64
    word_16 = words_16.deep_copy()
    word_15 = words_15.deep_copy()
    word_7 = words_7.deep_copy()
    word_2 = words_2.deep_copy()
	 
    word_i = (int(word_16) + sigma0(word_15)) % two64
    word_i = (word_i + int(word_7)) % two64
    word_i = (word_i + sigma1(word_2)) % two64
    return BitVector(intVal=word_i, size = 64)
	
def sigma0(word):
    temp1 = word.deep_copy()
    temp2 = word.deep_copy()
    temp3 = word.deep_copy()
	
    r_bv = (temp1 >> 1) ^ (temp2 >> 8) ^ (temp3.shift_right(7))
    return int(r_bv)
	
def sigma1(word):
    temp1 = word.deep_copy()
    temp2 = word.deep_copy()
    temp3 = word.deep_copy()
	
    r_bv = (temp1 >> 19) ^ (temp2 >> 61) ^ (temp3.shift_right(6))
    return int(r_bv)
	
	
def sigmaa(word):
    temp1 = word.deep_copy()
    temp2 = word.deep_copy()
    temp3 = word.deep_copy()
    r_bv = (temp1 >> 28) ^ (temp2 >> 34) ^ (temp3 >> 39) 
    return int(r_bv)
	
def sigmae(word):
    temp1 = word.deep_copy()
    temp2 = word.deep_copy()
    temp3 = word.deep_copy()
    r_bv = (temp1 >> 14) ^ (temp2 >> 18) ^ (temp3 >> 41) 
    return int(r_bv)
	
	
if __name__ == '__main__' :
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s file name\n" % sys.argv[0])
	sys.exit(1)
    message = sys.argv[1]
    hash(message)
