#!/usr/bin/env python
'''
Python IDA Patcher - Apply .dif file of IDA Debugger to executable file.
work on linux/windows/osx [ just tested on windows ]
ZeroDay Cyber Research
http://www.z3r0d4y.com
Ali Razmjoo
Ali@Z3r0D4y.Com
'''
__author__ = 'Ali Razmjoo'
import binascii,sys,re
def apply_exec(exec_file,dif_file):
		try:
			pe=open(exec_file,'rb').read(); df=re.findall(r'\s([0-9a-fA-F]+) ([0-9a-fA-F]+) ([0-9a-fA-F]+)',open(dif_file).read().replace(':',''))
		except:
			sys.exit('can\'t find the files')
		for add,d,rep in df:
			add=int(str(add),16);d=binascii.a2b_hex(d);rep=binascii.a2b_hex(rep)
			if pe[add] == d:
				pe = pe[:add]+rep+pe[add+1:]
			else:
				if pe[add] == rep:
					sys.exit('dif file already applied, can\'t apply again!')
				sys.exit('dif file can\'t apply on PE file')
		open(exec_file,'wb').write(pe)
if __name__ == "__main__":
	if len(sys.argv) is not 3:
		sys.exit('usage:\npython IDAPatcher.py PE_File(.exe) file.dif\n')
	apply_exec(sys.argv[1],sys.argv[2])
