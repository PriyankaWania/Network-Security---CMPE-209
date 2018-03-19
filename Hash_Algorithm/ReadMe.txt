		*** Hash Algorithm - SHA1 Algorithm ***

Plain text – Any length of the message (should be less than 2 raise to 64)
Message digest: 160 bits

5 steps to produce Hash:
	1. Appending padding bits: 100000 (In the order of 448 mod 512)
	2. Padding length: Remaining 64 bits are padded.
	3. Initialize Message digest buffer: To hold the intermediate and finale value. 160 
	    There are registers a,b,c … and so on each of 32 bits.
	     Initialized by some hexadecimal value
	4.Process:
		4 rounds (each round is same with primitive steps)
			Each round has 3 functions:
		-	Primitive function
		-	Constant value k
		-	20 byte word value (0-19)
