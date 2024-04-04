#!/usr/bin/env python
##
# Created by :  Bigendian Smalls
# Date:  1.31.2019
# 
# Copyright 2019  Bigendian Smalls
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
# to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# 
###
## parse a racf databse and dump password hashes
###
import sys
import argparse
from struct import pack,unpack

BLKSIZE		= 4096
T_SEG		= b'\x02'
T_BAM		= b'\x00'
T_DAT		= b'\x83'
T_IND		= b'\x8A'
T_EMP		= b'\xC3'
T_INDREG	= b'\x00'
T_INDNOR	= b'\x21'
T_INDGRP	= b'\x01'
T_INDUSR	= b'\x02'
T_INDDST	= b'\x04'
T_INDGEN	= b'\x05'
T_SEGBASE	= b'\x01'
IT_ALIAS	= b'\x62'
I_BLKID		= b'\x4e'

# 0=off, 1=info, 2=loud, 3=header/template info
DEBUG 		= 0

##
# Global variables
##
# This is required for record compression functions
recEntryName = ""

##
# process ICB
##
def processICB(icb):
	eyecatcher = icb[1010:1018].decode('cp500')
	num_bam =   int(icb[4:8].hex(),16)
	rba_ind1 =  int(icb[14:20].hex(),16)
	rba_bam1 =  int(icb[20:26].hex(),16)
	num_tmp =  int(icb[27:28].hex(),16)

	print("\tEyecatcher: {0:s}".format(eyecatcher))
	print("\tNum of BAM Blks: {0:d}".format(num_bam))
	print("\tRBA IND #1: {0:#6x}".format(rba_ind1))
	print("\tRBA BAM #1: {0:#6x}".format(rba_bam1))
	print("\tNum of tmp blks: {0:d}".format(num_tmp))

	print

##
# hex dump a block
##
def dumpBlock(blk,s_off):
	for i in range(0,128):
		l = i*32
		sys.stdout.write("{0:05X}:".format((l+s_off)))
		for j in range(l+0,l+32):
			p_byte=int.to_bytes(blk[j]).hex()
			sys.stdout.write("{0:s} ".format(p_byte))
		print("")
	print("")

##
# dump the hashes from the parsed hashes
##
def dumpHashes(hashes):
	# loop through hashes
	for h in hashes:
		# hash list record is (user,password)
		u = h[0]
		p = h[1]

		# how many pass parts are there
		if len(p) == 1:
			pt = p[0][0]
			pw = p[0][1]

			# DES type hash
			if pt == 12:
				# IBMUSER:$racf$*IBMUSER*F9XXXXXXXXXXXXX7
				print("{0:s}:$racf$*{0:s}*{1:s}".format(u,pw.hex().upper()))

			# Check KDFAES hashes
		else:
			pt1 = p[0]
			pwt = pt1[0]
			pw1 = pt1[1]
			pt2 = p[1]
			pht = pt2[0]
			pw2 = pt2[1]

			# KDFAES Password
			# printed parts are in the order req'd for john
			if pwt == 12 and pht == 100:
				print("{0:s}:$racf$*{0:s}*{1:s}{2:s}".format(u,pw2.hex().upper(),
				pw1.hex().upper()))

			# KDFAES Passphrase
			elif pwt == 87 and pht == 104:
				print("{0:s}:$racf$*{0:s}*{1:s}{2:s}".format(u,pw2.hex().upper(),
				pw1.hex().upper()))
			else:
				print("Debug: PH miss {0:s}".format(p))


##
# dump the user hashes to the screen
##
def parseHashes(users,hashes,f):
	""" un = name of user base segment
	    up = address of user base sement
	    upl = real lengeth of user prof
	    upr = offset of beg of profile
	    pnl = length of profile name
	    pn = profile name
	    pso = offset of prof start after prof name
	    ppr = remaining profile record
	    fn = individual field name
	    fl = indv field len
	    fd = indv field data """
	for u in users:
		if u[2]=="BASE":
			# username
			un = u[0]

			# list of users
			ulist = list()

			# found indicator
			found = False

			# userprofile address and length
			up = u[1]
			upl = int(f[up+5:up+9].hex(),16)

			# entire user profile record
			upr = f[up:up+upl]

			# profile name length & profile name
			pnl = int(f[up+17:up+19].hex(),16)
			pn = f[up+20:up+20+pnl]

			# actual profile starting offset
			pso = up + pnl + 20

			# entire profile record (minus offsets)
			ppr = f[pso:up+upl]

			# counter for parsing profile
			p = 0

			#print("User: {0:>8s} Seg: {2:4s} RBA {1:#x}".format(u[0],u[1],u[2]))
			while p < len(ppr):
				fn = ppr[p:p+1]
				fl = ord(ppr[p+1:p+2])

				# mark the extended fields high order bit set
				if fl >> 7 == 1:
					fl = int(ppr[p+2:p+5].hex(),16)
					fd = ppr[p+5:p+5+fl]
					op = p # save original p for printing
					p = p + 5 + fl

				#
				else:
					fd = ppr[p+2:p+2+fl]
					op = p # save original p for printing
					p = p + 2 + fl

				# we're only interested in pwd, phrase and ext pw/ext phr fields
				# 12 is password only for DES
				# 12 + 100 is KDFAES password (need both)
				# 87 can be phrase only for DES
				# 87 + 104 is KDFAES passphrase
				if ord(fn) in [12,87,100,104]:
					if DEBUG > 1:
						print("\tFound active profile + passfield.")
					if DEBUG > 0:
						print ("\t\t{0:X} {1:>8s}:fn:{2:3d}:len:{3:<#5x}:data:{4:s}".format(pso+op,un,ord(fn),fl,fd.hex().upper()))
					# populate our lists with user pass fields
					ulist.append([ord(fn),fd])
					found = True

		# after user complete, make sure we found at least 1 des or 2 kdfes and add user hashes to hash list
		if found:
			hashes.append([un,ulist])
			found = False

	if DEBUG > 0:
		print ("{0:d} users without hashes found".format(len(users)-len(hashes)))
		print ("{0:d} users with hashes found".format(len(hashes)))

	#return list of hashes
	return hashes

##
# parse index records
##
def parseIndexRecords(j,indBlk,blkoff,curr,users):
	global recEntryName
	indRecIdent= indBlk[curr:curr+1]                             # identificate of record
	indRecType = indBlk[curr+1:curr+2]                           # this record's type
	indRecLen  = int((indBlk[curr+2:curr+4]).hex(),16)   # length of this record

	# focus on the records we want
	rec = indBlk[curr:curr+indRecLen]

	# ugly debug
	if DEBUG > 2:
		print("{0:05X}".format(curr+blkoff) + ":" + rec.hex())

	recComp = int((rec[6:8]).hex(),16)
	recEntryNameLen = int((rec[8:10]).hex(),16)
	recSegOff = 12 + recEntryNameLen

	##
	# add compresed bytes back
	# note there cannot be a "compressed" entry until the entry prior has been
	# saved - the compression basically repeats the first XXX matching bytes of the
	# preview recEntryName so we have to save that off globally or return it/pass it back
	##
	if recComp != 0:
	    compBytes = recEntryName[0:recComp]
	else:
	    compBytes = ''
	recEntryName = compBytes + rec[12:recSegOff].decode('cp500')

	# if rec type is userrec -> x'21' && x'02'
	if indRecIdent== T_INDNOR and indRecType == T_INDUSR:
		segData = rec[recSegOff:indRecLen]

		# high debug
		if DEBUG > 1:
			print("\tSegData {0:s}".format(segData.hex()))

		# record segment type
		recSegType = segData[0:1]

		# ensure we have a non-alias
		if recSegType != IT_ALIAS:
			rba = 0
			rst = int(recSegType.hex(),16)
			sd = segData[1:]

			# parse segmentara for base
			for k in range(0,len(sd),7):
				segIdent = sd[k:k+1]

				# get segtype base
				if segIdent == T_SEGBASE:
					rba = int(sd[k+1:k+7].hex(),16)
					users.append([recEntryName,rba,"BASE"])
					if DEBUG > 0:
						print(("USER: Ind blk: {0:06X} rec: {1:02d} offset:{2:04X} " +
						"ident: {3:02X} type: {4:02X} len {5:3d} name {6:8s}").format(blkoff,
						j,curr,ord(indRecIdent),ord(indRecType),indRecLen, recEntryName) +
						" BASESEG: rba: {0:06X}".format(rba))

			#end if segIdent
		#end for k indcount
	#endif recident
	# if rec type is userrec

	curr = curr + indRecLen
	return curr,users

# end

##
# main prog function
##
def mainprog(ff):
	# read our file variable
	f = ff.read()

	# calculate # of 4096 blocks (per documentation)
	numblks = int(len(f) / 4096)
	s_block = 0

	# high db options
	if DEBUG > 0:
		print("Database length in bytes: {0:d}".format(len(f)))

	if DEBUG > 0:
		print("Number 4096 byte  blocks: {0:d}".format(numblks))


	# lists of users and user's hashes respectively
	users = list()
	hashes = list()

	# fist block is ICB (Header blocks)
	if DEBUG > 2:
		print("{0:04x}:{1:s}:ICB".format(0, "00".upper()))
		icb = f[0:4096]
		processICB(icb)

	# increment s_block
	s_block = s_block + 1

	for i in range(1,10):
		# next 9 blocks are template blocks
		blkoff = BLKSIZE * i
		if DEBUG > 3:
			print("{0:04x}:{1:s}:TEMPLATE".format(i, "xx".upper()))
			tmp_blk = f[blkoff:blkoff+4096]
			dumpBlock(tmp_blk,blkoff)

		# increment s_block
		s_block = s_block + 1

	# loop through all the blocks
	for i in range(s_block,numblks):

		# block size / type / id  variables
		blkoff = BLKSIZE * i
		bt = f[blkoff:blkoff+1]
		bid = f[blkoff+3:blkoff+4]


		# if block type is index
		if (bt == T_IND and bid == I_BLKID): # 0x8a && 0x4e
			# high debug
			if DEBUG > 1:
				print("{0:x}:{1:s}:IndexBlock".format(blkoff, T_IND.hex().upper()))

			# size of index
			indSz  = int((f[blkoff+1:blkoff+3]).hex(),16)

			# high debug
			if DEBUG > 1:
				print("\tindSz:" + hex(indSz))

			# index block
			indBlk = f[blkoff:blkoff+indSz]

			# index block type
			indType = indBlk[4:5]

			# if block type is index
			if indType == T_INDREG:  # 0x00

				# counter of index blocks
				indCount = int(indBlk[12:14].hex(),16)

				# first record offset ?? accounts for header?
				curr = 14

				# high debug
				if DEBUG > 1:
					print("\tNumRecs in Index block{0:6X}: {1:d}".format(blkoff,indCount))

				# for loop through blocks index entries
				for j in range(indCount):
					curr,users = parseIndexRecords(j,indBlk,blkoff,curr,users)


			# if block type is index
		# if block type is index
	# end for loop through blocks
	hashes = parseHashes(users,hashes,f)
	dumpHashes(hashes)

##
# Main method
##
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Parse binary RACF database file.  Help Screen.", epilog="End of help screen.")
	parser.add_argument('file', type=argparse.FileType('rb'), help="The file to be parsed.")
	parser.add_argument('-d','--debug', type=int, help="Debug Level (0,1,2,3).",default=0)
	args = parser.parse_args()
	DEBUG=args.debug
	mainprog(args.file)
