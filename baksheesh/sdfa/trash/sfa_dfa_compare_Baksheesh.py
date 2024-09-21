import random, secrets

if __name__=='__main__':
	# sbox and inv sbox of default
	#sbox = [0x0, 0x3, 0x7, 0xe, 0xd, 0x4, 0xa, 0x9, 0xc, 0xf, 0x1, 0x8, 0xb, 0x2, 0x6, 0x5]
	#inv_sbox = [0x0 ,0xa ,0xd ,0x1 ,0x5 ,0xf ,0xe ,0x2 ,0xb ,0x7 ,0x6 ,0xc ,0x8 ,0x4 ,0x3 ,0x9]  
	
	sbox = [0x3, 0x0, 0x6, 0xd, 0xb, 0x5, 0x8, 0xe, 0xc, 0xf, 0x9, 0x2, 0x4, 0xa, 0x7, 0x1]    # sbox of baksheesh 
	inv_sbox = [0x1 ,0xf ,0xb ,0x0 ,0xc ,0x5 ,0x2 ,0xe ,0x6 ,0xa ,0xd ,0x4 ,0x8 ,0x3 ,0x7 ,0x9]        # inv_sbox of baksheesh  
	
	#/* this list stores the count that whether the guess_key gives 1 at each bit_set or not */
	dfa_guess_key_list = [0 for _ in range(16)]		
	#/* this list stores the count that whether the guess_key gives 1 at each bit_set or not */
	sfa_guess_key_list = [0 for _ in range(16)]
	sfa_key_list = [0 for i in range(16)]
	dfa_key_list = [0 for i in range(16)]
	final_intersection = []

	key = secrets.randbelow(16)#0x3
	msg = secrets.randbelow(16)#0x1
	
	num_of_faults = 4
	for i in range(num_of_faults):
		#msg = secrets.randbelow(16)#0x1 
		
		print('msg, key:', msg, key)
		msg1 = 0x0
		cip = 0x0
		cip1 = 0x0
		bit_pos = i
		
		cip = sbox[msg]^key
		msg1 = msg ^(1 << bit_pos);		
		cip1 = sbox[msg1]^key;
		#print("faulty cip:\n", cip1);
		
		print("Bit Position::\n", bit_pos);
		#print("cip:\n", cip);
		print("input diff, output diff:\n", msg^msg1, cip^cip1);


		for guess_key in range(16):
			if ( (inv_sbox[(cip1^guess_key)] >> bit_pos) & 0x1 ) == ((msg1 >> bit_pos) & 0x1):
				sfa_guess_key_list[guess_key] = 1
			if(inv_sbox[(cip1^guess_key)]^inv_sbox[(cip^guess_key)]) == (1<<bit_pos):
				dfa_guess_key_list[guess_key] = 1


		print("\nsfa possible key list:")
		for guess_key in range(16):
			if sfa_guess_key_list[guess_key] == 1:
				print(guess_key, end = ' ')

		print("\ndfa possible key list:");
		for guess_key in range(16):
			if dfa_guess_key_list[guess_key] == 1:
				print(guess_key, end = ' ');
				
		for i in range(16):
			if sfa_guess_key_list[i] == 1:
				sfa_key_list[i] = sfa_key_list[i]+1
				
		for i in range(16):
			if dfa_guess_key_list[i] == 1:
				dfa_key_list[i] = dfa_key_list[i]+1  

		#sfa_key_list = list(result.elements())
		print('\nsfa intersecting keys::')
		for i in range(16):
			if sfa_key_list[i] == (bit_pos+1):
				print(i, end = ' ')
				
		print('\ndfa intersecting keys::')
		for i in range(16):
			if dfa_key_list[i] == (bit_pos+1):
				print(i, end = ' ')
		#sfa_key_list = intersection(sfa_key_list, sfa_guess_key_list)
		print("\n\n");
		
		for i in range(16):
			sfa_guess_key_list[i] = 0
			dfa_guess_key_list[i] = 0
	
	#print('Final sfa intersecting keys::\n', sfa_key_list)
	print('original key::', key)
	
	print('\nfinal intersecting keys::')
	for i in range(16):
		if (sfa_key_list[i] == (bit_pos+1)) and (dfa_key_list[i] == (bit_pos+1)):
			print(i, end = ' ')
			
	print('\n\n')


