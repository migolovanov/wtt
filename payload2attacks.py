#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import json
import argparse
try:
	import urllib.parse as urllib
except:
	import urllib



def get_arguments():
	"""
	CLI arguments parser
	"""
	parser = argparse.ArgumentParser(description='Payload => Attacks converter')
	parser.add_argument('-i', '--input',
						dest='input',
						default='./payloads',
						help='Path to folder containing payloads',
						required=True)
	parser.add_argument('-o', '--output',
						dest='output',
						default='./attacks',
						help='Path to folder where generated attacks should be saved',
						required=True)
	parser.add_argument('-m', '--method',
						dest='method',
						default='all',
						help='Attacks with methods, e.g.: get,post,header or all ',
						required=True)
	result = parser.parse_args()
	return result


class Attack():
	def __init__(self, attack, count, idx, file):
		"""
		class of attack, that willb e written to file
		body:		 body for attack-request
		description:  attack description
		headers:	  headers for attack-requst
		id:		   attack ID
		method:	   HTTP-method for attack-request
		status_code:  expected status code (403 - block, any other - pass)
		url:		  url for attack-request


		params:
		attack  attack,parsed from file
		count   count of leading zeroes in attack ID
		idx	 current index number of attack
		file	name of file with payloads
		"""
		self.id = "%s__%s" % (file.split('/')[1].split('.')[0].split('_')[0].upper(),
			str(idx+1).zfill(count))
		self.method = "GET"
		self.status_code = 403
		try:
			self.payload = attack.decode('utf8')
		except:
			self.payload = attack
		self.body = None
		self.description = None
		self.headers = None
		self.url = None

	def set_get(self):
		"""
		form request with payload in GET parameter
		"""
		self.body = None
		self.method = "GET"
		self.id = self.id.replace("__", "_%s_" % self.method)
		self.url = "?test=%s" % urllib.quote(urllib.unquote(self.payload).encode('utf8'))
		self.headers = { "Connection": "close",
					"User-Agent": "Mozilla/5.0 Windows NT 6.3; Win64; x64 AppleWebKit/537.36 KHTML, like Gecko Chrome/44.0.2403.107 Safari/537.36"}

	def set_post(self):
		"""
		form request with payload in POST parameter
		"""
		self.url = None
		self.method = "POST"
		self.id = self.id.replace("__", "_%s_" % self.method)
		self.body = "test=%s" % urllib.quote(urllib.unquote(self.payload).encode('utf8'))
		self.headers = { "Connection": "close",
					"User-Agent": "Mozilla/5.0 Windows NT 6.3; Win64; x64 AppleWebKit/537.36 KHTML, like Gecko Chrome/44.0.2403.107 Safari/537.36",
					"Content-Type": "application/x-www-form-urlencoded"}

	def set_header(self):
		"""
		form request with payload in header
		"""
		self.url = None
		self.body = None
		self.method = "GET"
		self.id = self.id.replace("__", "_%s_" % "HEADER")
		self.headers = { "Connection": urllib.quote(urllib.unquote(self.payload).encode('utf8')),
					"User-Agent": "Mozilla/5.0 Windows NT 6.3; Win64; x64 AppleWebKit/537.36 KHTML, like Gecko Chrome/44.0.2403.107 Safari/537.36"}

def get_files(folder):
	"""
	get file list from specified folder

	params:
	folder  folder including files with payloads
	"""
	files = list()
	for root,dirs,file in os.walk(folder, topdown=False):
		for name in file:
			files.append(os.path.join(root,name))
	return files

def write_file(method, file, args, data):
	"""
	write file with generated attacks

	params:
	args	CLI arguments
	data	list with generated attacks
	file	name of file with payloads
	method  HTTP-method for attacks (GET,POST)
	"""
	filename = "%s/%s_%s.json" % (  args.output,
									file.split('/')[1].split('.')[0].split('_')[0].lower(),
									method)
	with open(filename, 'w') as f:
		json.dump(data, f)

def main(args):
	"""
	main function

	params:
	args  CLI arguments
	"""
	if args.method == "all":
		methods = ["get","post","header"]
	else:
		methods = args.method.split(",")

	filelist = get_files(args.input)
	for method in methods:
		print("Method: %s" % method.upper())
		for file in filelist:
			payloads=open(file,'r').readlines()
			temp = list()
			print("\tProcessing file: %s...\t" % (file))
			for idx,payload in enumerate(payloads):
				attack = Attack(payload, len(str(len(payloads))), idx, file)
				if method == "get":
					attack.set_get()
				elif method == "post":
					attack.set_post()
				else:
					attack.set_header()
				temp.append(attack.__dict__)
			write_file(method,file,args,temp)

opts = get_arguments()
main(opts)
