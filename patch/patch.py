#!/usr/bin/python

import sys
import string

'''
simple script to patch the mistrust elf binary to work 
with a given flag and mac
'''

offset = 4288 # offset of the 48-byte encrypted flag in the elf given binary
max_size_flag = 40 # maximum size flags that can be encrypted into the 48-byte target buffer

def KSA(key):
    	keylength = len(key)
    	S = range(256)
    	j = 0
    	for i in range(256):
        	j = (j + S[i] + ord(key[i % keylength])) % 256
        	S[i], S[j] = S[j], S[i]
    	return S

def PRGA(S, num_bytes):
    	i = 0
    	j = 0
    	ks = ""
    	for index in range(num_bytes):
        	i = (i + 1) % 256
        	j = (j ^ S[i]) % 256 # in real rc4, the xor would be an add
        	S[i], S[j] = S[j], S[i]

        	ks += chr(S[(S[i] + S[j]) % 256])
    	return ks

def crypt(key, plain):
    	S = KSA(key)
    	ks = PRGA(S, len(plain))
	
    	cipher = "".join( chr(ord(ks[i]) ^ ord(plain[i])) for i in range(len(plain)) )
    	return cipher

def encrypt_flag(flag, mac):
	key = mac.decode('hex')
	plain = "".join("\x00" for i in range(8))
	plain += flag
	plain += "".join("\x00" for i in range(max_size_flag - len(flag)))
	tmp = crypt(mac[:6].decode('hex'), plain)
	cipher = crypt(mac[6:].decode('hex'), tmp)
	return cipher


def find_offset(url, substr):
	with open(url, "rb") as f:
    		bytes = f.read()
    		n = bytes.find(substr.decode('hex'))
		print n

def ishex(s):
	for c in s:
		if not c in string.hexdigits: 
			return False
	return True

def patch(url, flag, mac):
	if len(flag) > max_size_flag:
		print "flag should be at most 40 chars"
		exit()
	if len(mac) is not 12 or not ishex(mac):
		print "invalid mac"
		exit()
	enc_flag = encrypt_flag(flag, mac)
	with open(url, "r+b") as f:
		f.seek(offset)
    		f.write(enc_flag)

if len(sys.argv) is not 4:
	print "Usage: patch.py <mistrust_url> <flag> <mac>"
else:
	patch( str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3])) 
