# Here the left sbox has been taken as 0th sbox
import os
import sys

class draw:
	def __init__(self, cipher, rounds, version, imp_round):
		# gap = gap between sboxes in each round. Round gap = gap between two consequitive rounds. 
		self.cipher = cipher
		self.name = 'latex_file.tex'
		self.version = version
		self.rounds = rounds
		self.imp_round = imp_round
		self.block_size = version

		self.imp_gap = 0

		if self.version == 64:
			self.sbox_side_len = 1
			self.gap = 0.2
			# delta = gap between sbox lenth and nearest bit line
			self.delta = 0.1
			self.bit_line_len = 1
			self.round_gap = 4

		if self.version == 128:
			self.sbox_side_len = 0.54
			self.gap = 0.07
			self.delta = 0.07
			self.bit_line_len = 0.5
			self.round_gap = 3.5

		# size is for size of the xor and sbox sign
		if self.version == 64:
			self.size = 'small'
		else:
			self.size = 'tiny'


		# sbox line gap is the gap between bit lines 
		self.sbox_line_gap = (self.sbox_side_len/3) - (2*(self.delta)/3)

		# defining colors for bit and sbox. If the bit is active then the line will be colored as red and for sbox, if any bit of the sbox is in active bit list then the sbox will be activated.
		self.default_bit_color = "gray!30"
		self.active_bit_color = "red!80"

		self.default_sbox_color = "white"
		self.active_sbox_color = "gray!30"


	# defining the linear layer of the given cipher
	def linear_layer(self, bit_num):

		# next 64 and 128 bit permutations are for gift versions
		if self.cipher == 'gift':
			if self.version == 64:
				perm = [ 0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3, 4, 21, 38, 55, 52, 5, 22    , 39, 36, 53, 6, 23, 20, 37, 54, 7, 8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11, 12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15]

			if self.version == 128:
				perm = [0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3, 4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7, 8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11, 12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15, 16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19, 20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23, 24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27, 28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31]


		# next permutation is for present
		if self.cipher == 'present':
			perm = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

		return perm[bit_num]


	def console_commands(self):
		# run pdflatex in the console and redirect the output in dev/null and if error occured then it again run, prints the output and exit from main function
		if (os.system('pdflatex ' + self.name + '>> /dev/null')):
			os.system('pdflatex ' + self.name)
			sys.exit(0)
		
		# removing the unnecessary files generated by latex
		file_name = self.name
		file_name = file_name.replace('.tex', '')
		os.system('rm ' + file_name + '.aux')
		os.system('rm ' + file_name + '.log')
		os.system('rm ' + self.name)

		# open the pdf generated by latex
		os.system('xdg-open ' + file_name + '.pdf')


	# initializing the latex file.
	def init_latex_file(self):
		fileobj = open(self.name, 'w')

		# printing initial document class and needed packages in latex file.
		fileobj.write("\n\\documentclass[12pt,a4paper ]{report}	")
		fileobj.write("\n\\usepackage[a4paper,total={8in,10in}]{geometry}	")
		fileobj.write("\n\\usepackage{amsmath,amsthm}")
		fileobj.write("\n\\usepackage{tikz}	")
		fileobj.write("\n\\usepackage{xcolor}")
		fileobj.write("\n\\usepackage{siunitx}")
		fileobj.write("\n\\usetikzlibrary{positioning}")
		fileobj.write("\n")
		fileobj.write("\n\\begin{document}")
		fileobj.write("\n\\begin{center}")
		fileobj.write("\n")
		fileobj.write("\n\\begin{tikzpicture}")

		fileobj.close()
		

	# ending the latex file.
	def end_latex_file(self):
		fileobj = open(self.name, 'a')

		fileobj.write("\n\\end{tikzpicture}")
		fileobj.write("\n\\end{center}")
		fileobj.write("\n\\end{document}")
		fileobj.write("\n")	

		fileobj.close()


	# drawing sbox depending upon round num and sbox number
	def draw_sbox(self, color, round_num, sbox_num):
		fileobj = open(self.name, "a")

		# # for imp input
		# if ((round_num == self.rounds - 1) and (sbox_num in [0, 1, 2, 3])):
		# 	color = "green!30"

		# if ((round_num == self.rounds) and (sbox_num in [0, 4, 8, 12])):
		# 	color = "green!30"

		# # for qr1
		# if ((round_num == self.rounds - 1) and ((sbox_num) in [4, 5, 6, 7])):
		# 	color = "blue!20"

		# if ((round_num == (self.rounds)) and ((sbox_num) in [1, 5, 9, 13])):
		# 	color = "blue!20"

		# # for qr2
		# if ((round_num == self.rounds - 1) and ((sbox_num) in [8, 9, 10, 11])):
		# 	color = "black!20"

		# if ((round_num == (self.rounds)) and ((sbox_num) in [2, 6, 10, 14])):
		# 	color = "black!20"

		# # for qr3
		# if ((round_num == self.rounds - 1) and ((sbox_num) in [12, 13, 14, 15])):
		# 	color = "yellow!20"

		# if ((round_num == (self.rounds)) and ((sbox_num) in [3, 7, 11, 15])):
		# 	color = "yellow!20"

		# setting x_coordinate and y_coordinate of the sbox.
		x_coordinate = - (sbox_num * self.sbox_side_len) - (sbox_num * self.gap)
		y_coordinate = - ((round_num - 1) * self.round_gap) - self.bit_line_len - (self.sbox_side_len/2) - self.imp_gap


		fileobj.write("\n	\\node[fill = " + color + ", rounded corners] (S_" + str(round_num) + "_" + str(sbox_num) + ") at (" + str(x_coordinate) + ", " + str(y_coordinate) + ") [draw,thick,minimum width=" + str(self.sbox_side_len) + " cm,minimum height=" + str(self.sbox_side_len) + " cm]{\\" + str(self.size) + " S}; ")

		fileobj.close()



	# Draw initial input bit lines of the cipher.
	def draw_init_sbox_input_line(self, color, round_num, bit_num):
		fileobj = open(self.name, 'a')

		# # to give input lines after "contradiction" for imp input
		# # for qr0
		# if ((self.imp_gap != 0) and (round_num == self.imp_round - 1) and ((bit_num//4) in [i for i in [0, 1, 2, 3]])):
		# 	color = "green!70"

		# # for qr1
		# if ((self.imp_gap != 0) and (round_num == self.imp_round - 1) and ((bit_num//4) in [i for i in [4, 5, 6, 7]])):
		# 	color = "blue!70"

		# # for qr2
		# if ((self.imp_gap != 0) and (round_num == self.imp_round - 1) and ((bit_num//4) in [i for i in [8, 9, 10, 11]])):
		# 	color = "black!70"

		# # for qr3
		# if ((self.imp_gap != 0) and (round_num == self.imp_round - 1) and ((bit_num//4) in [i for i in [12, 13, 14, 15]])):
		# 	color = "yellow!70"



		sbox_num = bit_num//4;

		# finding sbox coordinates  
		sbox_x_coordinate = - (sbox_num * self.sbox_side_len) - (sbox_num * self.gap)
		sbox_y_coordinate = - (round_num * self.round_gap) - self.bit_line_len - (self.sbox_side_len/2) - self.imp_gap
	   
		# setting x_coordinate and y_coordinate of the sbox.
		in_x_coordinate = sbox_x_coordinate + self.sbox_side_len/2 - self.delta - ((bit_num%4) * self.sbox_line_gap)
		in_y_coordinate = sbox_y_coordinate + self.bit_line_len + (self.sbox_side_len/2) 

		out_x_coordinate = sbox_x_coordinate + (self.sbox_side_len/2) - self.delta - ((bit_num%4) * self.sbox_line_gap)
		out_y_coordinate = sbox_y_coordinate + (self.sbox_side_len/2)

		fileobj.write("\n	\\draw[->, " + color + ", thick] (" + str(in_x_coordinate) + "," + str(in_y_coordinate) + ") -- (" + str(out_x_coordinate) + "," + str(out_y_coordinate) + "); ")

		# the if conditions for gift cipher. In the first round there are no xor signs. For the version 64 the xor bit positions are 0,1. For the version 128 the xor bit positons are 2,3
		if (self.cipher == 'gift'):
			# # uncomment the lower 3 lines to remove xor at 0th round
			# if (round_num == 0):
			# 	fileobj.close()
			# 	return

			if ((self.version == 128) and ((bit_num%4) in [0,3])):
				fileobj.close()
				return

			if ((self.version == 64) and (bit_num not in [3, 7, 11, 15, 19, 23, 63]) and ((bit_num%4) in [2,3])):
				fileobj.close()
				return

		# giving xor at input lines. Its x_coordinate will be same as input lines and y_coordinate = half of bit line's distance from bit line's starting distance.
		fileobj.write("\\node (xor_" + str(round_num) + "_" + str(bit_num) + ") at (" + str(in_x_coordinate) + "," + str(in_y_coordinate - self.bit_line_len/2)+ ") {\\" + str(self.size) + "$\\oplus$};")

		fileobj.close()



	# Draw last output bit lines of the cipher.
	def draw_sbox_output_line(self, color, round_num, bit_num):
		fileobj = open(self.name, 'a')

		sbox_num = bit_num//4

		# finding sbox coordinates  
		sbox_x_coordinate = - (sbox_num * self.sbox_side_len) - (sbox_num * self.gap)
		sbox_y_coordinate = - ((round_num - 1)* self.round_gap) - self.bit_line_len - (self.sbox_side_len/2) - self.imp_gap
	   
		# setting x_coordinate and y_coordinate of the sbox.
		in_x_coordinate = sbox_x_coordinate + self.sbox_side_len/2 - self.delta - ((bit_num%4) * self.sbox_line_gap)
		in_y_coordinate = sbox_y_coordinate - (self.sbox_side_len/2) 

		out_x_coordinate = sbox_x_coordinate + self.sbox_side_len/2 - self.delta - ((bit_num%4) * self.sbox_line_gap)
		out_y_coordinate = sbox_y_coordinate - (self.bit_line_len/2) - (self.sbox_side_len/2) 

		if((round_num - 1 )< self.rounds):
			fileobj.write("\n	\\draw[-, " + color + ", thick] (" + str(in_x_coordinate) + ", " + str(in_y_coordinate) + ") -- (" + str(out_x_coordinate) + "," + str(out_y_coordinate) + " ); ")

		# giving xor at last input lines
		if((round_num - 1)== rounds):
			out_y_coordinate = sbox_y_coordinate - self.bit_line_len - (self.sbox_side_len/2)
			fileobj.write("\n	\\draw[->, " + color + ", thick] (" + str(in_x_coordinate) + "," + str(in_y_coordinate) + ") -- (" + str(out_x_coordinate) + "," + str(out_y_coordinate) + "); ")

			fileobj.write( "\\node at (" + str(in_x_coordinate) + "," + str(in_y_coordinate - self.bit_line_len/2) + "){$" + str(self.size) + "\\oplus$};")

		fileobj.close()



	# To draw permutation bit lines of the cipher.
	def draw_permutation_lines(self, color, round_num, bit_num):
		fileobj = open(self.name, 'a')

		if (round_num == self.rounds):
			color = "black!70"

		if (round_num == self.rounds - 1):
			color = "gray"
		# # for imp input
		# # for qr0
		# if ((round_num == self.rounds - 1) and ((bit_num//4) in [0, 1, 2, 3])):
		# 	color = "green!70"

		# if ((round_num == (self.rounds)) and ((bit_num//4) in [0, 4, 8, 12])):
		# 	color = "green!70"

		# # for qr1
		# if ((round_num == self.rounds - 1) and ((bit_num//4) in [4, 5, 6, 7])):
		# 	color = "blue!70"

		# if ((round_num == (self.rounds)) and ((bit_num//4) in [1, 5, 9, 13])):
		# 	color = "blue!70"

		# # for qr2
		# if ((round_num == self.rounds - 1) and ((bit_num//4) in [8, 9, 10, 11])):
		# 	color = "black!70"

		# if ((round_num == (self.rounds)) and ((bit_num//4) in [2, 6, 10, 14])):
		# 	color = "black!70"

		# # for qr3
		# if ((round_num == self.rounds - 1) and ((bit_num//4) in [12, 13, 14, 15])):
		# 	color = "yellow!70"

		# if ((round_num == (self.rounds)) and ((bit_num//4) in [3, 7, 11, 15])):
		# 	color = "yellow!70"

		# giving the sbox output line from the previous layer
		self.draw_sbox_output_line(color, round_num, bit_num)

		sbox_num = bit_num//4

		sbox_in_x_coordinate = - (sbox_num*self.sbox_side_len) - (sbox_num*self.gap)
		sbox_in_y_coordinate = - ((round_num - 1)*self.round_gap) - self.bit_line_len - (self.sbox_side_len/2) - self.imp_gap

		# taking the permutation of the bit
		sbox_num = self.linear_layer(bit_num)//4
		sbox_out_x_coordinate = - (sbox_num*self.sbox_side_len) - (sbox_num*self.gap)
		sbox_out_y_coordinate = - (round_num*self.round_gap) - self.bit_line_len - (self.sbox_side_len/2)

		in_x_coordinate = sbox_in_x_coordinate + self.sbox_side_len/2 - self.delta - ((bit_num%4)*self.sbox_line_gap)
		in_y_coordinate = sbox_in_y_coordinate - (self.sbox_side_len/2) - (self.bit_line_len/2)

		out_x_coordinate = sbox_out_x_coordinate + self.sbox_side_len/2 - self.delta - ((self.linear_layer(bit_num)%4)*self.sbox_line_gap)
		out_y_coordinate = sbox_out_y_coordinate + (self.sbox_side_len/2) + self.bit_line_len - self.imp_gap

		fileobj.write("\n	\\draw[ " + color + ", thick] ( " + str(in_x_coordinate) + ", " + str(in_y_coordinate) + ") -- (" + str(out_x_coordinate) + " , " + str(out_y_coordinate) + ");")

		self.draw_init_sbox_input_line(color, round_num, self.linear_layer(bit_num))

		fileobj.close()


	def load_active_bits(self):
		fp = open('input_file.txt', 'r+')    
		
		active_bit = []
		# prints elements in the line at a desired line number     
		for line_num, line in enumerate(fp):    
			if line_num != 0:
				# replaceing '\n' from each line and taking int numbers from each line
				line = line.replace('\n', '')
				temp_line = [int(i) for i in line.split(' ')] 

				active_bit.append(temp_line)
		
		return active_bit


	def draw_bar(self):
		# for sbox in range() -- update this
		in_x_coordinate = - (8 * self.sbox_side_len) - (8 * self.gap)
		in_y_coordinate = 0

		out_x_coordinate = in_x_coordinate
		out_y_coordinate = - ((self.rounds) * self.round_gap) - self.bit_line_len

		fileobj = open(self.name, 'a')
		fileobj.write("\n	\\draw[ultra thick, red] ( " + str(in_x_coordinate) + ", " + str(in_y_coordinate) + ") -- (" + str(out_x_coordinate) + " , " + str(out_y_coordinate) + ");")
		fileobj.close()



	# this function generates the latex file.
	def generate_latex_file(self):
		self.init_latex_file()
	   
		active_bit = self.load_active_bits()

		for round_num in range(self.rounds + 1):
			if (round_num == imp_round):
				self.imp_gap = 3

				for bit in range(self.block_size):
					self.draw_init_sbox_input_line(self.default_bit_color, round_num-1, bit)

			# self.draw_sbox(self.active_sbox_color, round_num, bit//4)

			for bit in range(self.block_size):
				# check whether the bit is active or not
				if bit in active_bit[round_num]:
					color = self.active_bit_color
				else:
					color = self.default_bit_color


				# for initial input round
				if (round_num == 0):
					self.draw_init_sbox_input_line(color, round_num, bit)
					continue

				# drawing sbox at rounds
				if((bit%4) == 0):
					sbox_bit = {bit, bit+1, bit+2, bit+3}
					if len(sbox_bit.intersection(set(active_bit[round_num]))) != 0:
						self.draw_sbox(self.active_sbox_color, round_num, bit//4)
					else:
						self.draw_sbox(self.default_sbox_color, round_num, bit//4)


				# drawing permutation layer in rounds.
				self.draw_permutation_lines(color, round_num, bit);

		fileobj = open(self.name, 'a')
		fileobj.write("\n \\node[draw, color = red, minimum width = 8cm, minimum height = 1cm, above = 2cm of S_" + str(imp_round) + "_" + str(self.block_size/8) + "] (a) {\\large Contradiction};")

		# # giving round numbers and key numbers. For gift 128 the xoring positions are 1,2 hence give the name as xor_round_1.
		# fileobj.write("\n \\node[below = 3cm of S_" + str(2) + "_0] (a) {($hw \\leq 1$)};")
		# fileobj.write("\n \\node[above = 1cm of S_" + str(3) + "_0] (a) {($hw(S) > 1$};")
		# # fileobj.write("\n \\node[above = 1cm of S_" + str(3) + "_0] (a) {($hw(4i:4i + 3 : 0 \\leq i < 16 ) > 1$)};")

		# fileobj.write("\n \\node[right = 1mm of S_" + str(3) + "_0] (a) {{$R^{25}$}};")
		# fileobj.write("\n \\node[right = 1mm of xor_" + str(3) + "_1] (a) {{$K^{25}$}};")

		# fileobj.write("\n \\node[right = 1mm of S_" + str(4) + "_0] (a) {{$R^{26}$}};")
		# fileobj.write("\n \\node[right = 1mm of xor_" + str(4) + "_1] (a) {{$K^{26}$}};")

		# # fileobj.write("\n \\node[right = 1mm of S_" + str(5) + "_0] (a) {{$R^{27}$}};")
		# # fileobj.write("\n \\node[right = 1mm of xor_" + str(5) + "_1] (a) {{$K^{27}$}};")

		# fileobj.write("\n \\node[right = 1mm of S_" + str(2) + "_0] (a) {{$R^{24}$}};")
		# fileobj.write("\n \\node[right = 1mm of xor_" + str(2) + "_1] (a) {{$K^{24}$}};")

		# fileobj.write("\n \\node[right = 1mm of S_" + str(1) + "_0] (a) {{$R^{23}$}};")
		# fileobj.write("\n \\node[right = 1mm of xor_" + str(1) + "_1] (a) {{$K^{23}$}};")
		fileobj.close()


		# self.draw_bar()
		self.end_latex_file()



if __name__ == '__main__':
	# cipher = 'present'
	cipher = 'gift'
	rounds = 4

	# version = 64
	version = 128

	imp_round = 0

	a = draw(cipher, rounds, version, imp_round)

	a.generate_latex_file()
	a.console_commands()




