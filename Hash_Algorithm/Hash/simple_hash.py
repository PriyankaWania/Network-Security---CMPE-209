#!/usr/bin/env python
import sys

from BitVector import *
from glob import *
import time

def main():

        print "\n **** 1. Please make sure the 'input' directory containing the test files is in the same directory as the python file ****"
        print "                 2. Please make sure the 'output' directory is created to store the output of the test files \n"
        time.sleep(3)
        
	#Scan your directory (current), compute the hash of all your files.
	Scan = glob('input/*.*')
	Count = 0

	while(Count < len(Scan)):
		bit_vector = BitVector(filename = Scan[Count])
		
		#1. Initialize the hash to all zeros.
		#This bit vector will hold exactly 32 bits, all initialized to the 0 bit value.
		
		Hashing = BitVector(size = 32)
		
		# If no more data to read,
		# Stop after shifting
		while (bit_vector.more_to_read):
			#2. Scan the file one byte (8bits) at a time.
			bit_vector1 = bit_vector.read_bits_from_file(8)
			
			#3. Circularly shift bit pattern in hash to left by 4 pos, before a new byte is read from the file
			Hashing << 4
			
			#4. XOR the new byte read from the file with the least significant byte (the rightmost) of the hash.
			Hashing[0:8] = bit_vector1 ^ Hashing[0:8]
						
		
		bit_vector.close_file_object()
			
		# Convert to Hex
		Hex_Hash = Hashing.getHexStringFromBitVector()
	
		# Dump the hash values in some output file.
		try:
		        
		        Output_file = open('output/Output_File.txt', 'a')
		        Output_file.write('\n')
		        Output_file.write(Scan[Count])
		        Output_file.write(":")
		        Output_file.write(Hex_Hash)
		        Output_file.close()
		        Count += 1
		except IOError:
		        print "\n\n                             **** ERROR !!! **** "
		        print" \n **** Please create a directory named 'output' to dump the hash values. **** \n\n"
		        sys.exit()
		        
	print "\n Dumping the hash values in 'output' directory ..."
	time.sleep(3)
	print " \n Done .... \n\n Please check the 'output' directory for the hash values of the input text files.\n"
	
main()
