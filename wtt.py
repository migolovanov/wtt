#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys
import json
import time
import codecs
import random
try:
	import urllib.parse as urllib
except:
	import urllib
import argparse
import multiprocessing as mp
from multiprocessing.managers import BaseManager
from jinja2 import Template
from itertools import repeat
from collections import OrderedDict
from requests import Request, Session, packages, exceptions, auth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
try:
	from tqdm import tqdm
	tqdm_enabled = 1
except ImportError:
	print("INFO: tqdm is not installed, no progress bar will be displayed")
	tqdm_enabled = 0

class WttManager(BaseManager): pass

def Manager():
	m = WttManager()
	m.start()
	return m

class Bar(object):
	"""
	tqdm progress bar object
	"""

	def __init__(self):
		"""
		desc:     label of progressbar (file name)
		position: line number of progress bar (file position in array)
		progress: bar object itself
		total:    total number of attacks in file
		"""

		self.desc = None
		self.position = None
		self.progress = None
		self.total = None

	def set(self,total,desc,position):
		"""
		set progress bar with specified parameters

		params:
		desc      label of progressbar (file name)
		position  line number of progress bar (file position in array)
		total     total number of attacks in flie
		"""

		self.total = total
		self.desc = desc
		self.position = position

		if os.name == 'nt':
			self.progress = tqdm(total=self.total,
			desc=self.desc,
			ascii=True,
			mininterval=0.33)
		else:
			self.progress = tqdm(total=self.total,
			desc=self.desc,
		#	position=self.position,
		#	leave=False,
			ascii=False,
			mininterval=0.33)

	def update(self):
		"""
		update progress bar status: increment 1
		"""

		self.progress.update()

WttManager.register('Bar', Bar)

class Url(object):
	"""
	parsed url object
	"""

	def __init__(self):
		"""
		parameters: request GET-parameters from URL
		path:       path to specified URL
		port:		port to connect
		protocol:   protocol used to connect (http/https)
		host:       host used to connect (ip address/hostname)
		"""

		self.parameters = ""
		self.path = ""
		self.port = 80
		self.protocol = "http"
		self.host = None

	def parse(self, url):
		"""
		Checks if URL is RFC-valid and parses it to elements

		params:
		url  url parameter from CLI arguments
		"""

		regex = re.match("(https?:\/\/)?([^\/:]*)(:[0-9]*)?(\/.*)?(\?.*)?",url)

		if regex.group(1) != None:
			self.protocol = regex.group(1).split(':',1)[0]
			if self.protocol == "https":
				self.port = 443
		self.host = regex.group(2)

		if (not re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$",
						  self.host)
			and not re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
							self.host)):
				raise Exception("invalid hostname")

		if regex.group(3) != None:
			self.port = regex.group(3).split(':',1)[1]

		if regex.group(4) != None:
			self.path = re.sub(r"^\/", "", regex.group(4))

		if regex.group(5) != None:
			self.parameters = re.sub(r"^\?", "", regex.group(5))

class Attack(object):
	"""
	attack object
	"""

	def __init__(self,attack):
		"""
		body:               body of request
		description:        attack description
		headers:            headers of request (dict object)
		id:                 attack id
		method:             HTTP-method of request
		payload:            attack payload, that is checked
		status_code:        expected status code from server (403: block, other: allow)
		url:                request URL
		actual_status_code: status code, recieved by waf of application
		auth:               auth type (basic/digest/http/None)
		auth_params:        request parameters to perform authentication
		auth_success:       regex pattern for successful check of http auth
		auth_url:           url to send authentication request
		csrf:               csrf status (enabled/disabled)
		csrf_name:          name of variable, where csrf token is stored
		csrf_sendname:      name of variable, that should be used in requests
		csrf_value:         value of csrf variable
		detect_type:        type of blocked attack detection (status_code/pattern/regex)
		failed:             indicates, that check was failed
		false_negative:     indicates, that attack should be blocked, but wasn't
		false_positive:     indicates, that attack shoundn't be blocked, but was
		file:               file name of currently processed file
		host:               hostname where requests are sent
		pattern:            pattern for pattern/requests type of blocked attack detection
		pattern_found:      position (for pattern) or value of found pattern (regex)
		protocol:           protocol for server connection (http/https)
		raw_request:        formatted full raw request (for report)
		response:           response object
		uri:                url including protocol, host etc.

		params:
		attack  single attack from file
		"""

		self.body = attack["body"]
		self.description = attack["description"]
		self.headers = attack["headers"]
		self.id = attack["id"]
		self.method = attack["method"]
		self.payload = attack["payload"]
		self.status_code = attack["status_code"]
		self.url = attack["url"]
		self.actual_status_code = None
		self.auth = None
		self.auth_params = None
		self.auth_success = None
		self.auth_url = None
		self.csrf = False
		self.csrf_name = None
		self.csrf_sendname = None
		self.csrf_value = None
		self.detect_type = None
		self.failed = None
		self.false_negative = None
		self.false_positive = None
		self.file = None
		self.host = None
		self.pattern = None
		self.pattern_found = None
		self.protocol = None
		self.raw_request = None
		self.response = None
		self.uri = None

	def send(self, url, session):
		"""
		prepare request and sends it to server

		params:
		url      Url object with parsed URL
		session  current requests session
		"""
		if "Connection" not in self.headers:
			self.headers["Connection"] = "keep-alive"
		self.host = url.host
		self.protocol = url.protocol

		if self.url == None:
			if url.path == None:
				self.url = ""
			else:
				self.url = url.path
		else:
			self.url = ''.join([url.path, re.sub(r"^\/","",self.url), url.parameters])

		if self.description == None or self.description.lower().find('csrf') == -1:
			if self.csrf and self.method.upper() == "POST":
				self.get_csrf_token(session, self.uri)
				if self.body != None:
					self.body += "&"
				if self.csrf_sendname != None:
					self.body += "%s=%s" % (self.csrf_sendname, self.csrf_value)
				else:
					self.body += "%s=%s" % (self.csrf_name, self.csrf_value)
		
		self.uri = "%s://%s:%s/%s" % (self.protocol,
			self.host,
			url.port,
			self.url)
			
		if "Referer" not in self.headers:
			self.headers["Referer"] = self.uri.split("?")[0]
		
		request = Request(  self.method.upper(),
							self.uri,
							headers=self.headers,
							data=self.body,
							cookies=session.cookies)

		if self.auth == "basic" or self.auth == "digest":
			request.auth = self.auth_basic_digest()

		response = session.send(request.prepare(), verify=False, allow_redirects=False)
		self.raw_request = pretty_raw_request(response)
		self.actual_status_code = response.status_code
		self.response = response.text

	def get_csrf_token(self, session, url):
		"""
		perform GET-request to retrieve CSRF-token

		params:
		url      Url object with parsed URL
		session  current requests session
		"""

		request = Request("GET", url, headers=self.headers, cookies=session.cookies)
		response = session.send(request.prepare(), verify=False)

		if self.csrf_name in response.headers:
			self.csrf_value = response.headers[self.csrf_name]

		if self.csrf_name in response.cookies:
			self.csrf_value = response.cookies[self.csrf_name]
		else:
			regex = re.search(r"%s=(['\"])?([\w\d]*)" % self.csrf_name, response.text)
			if regex != None:
				self.csrf_value = regex.group(2)

	def auth_basic_digest(self):
		"""
		return data for basic/digest auth
		"""

		params = dict()
		for item in self.auth_params.split(','):
			params[item.split("=")[0]] = item.split("=")[1]

		if self.auth.lower() == "basic":
			try:
				return auth.HTTPBasicAuth(params["login"],params["password"])
			except:
				sys.exit("ERROR: Basic auth has no login and password fields")

		if self.auth.lower() == "digest":
			try:
				return auth.HTTPDigestAuth(params["login"],params["password"])
			except:
				sys.exit("ERROR: Digest auth has no login and password fields")

	def auth_http(self, session):
		"""
		send request to http auth

		params:
		session  current requests session
		"""

		params = dict()
		for item in self.auth_params.split(','):
			params[item.split("=")[0]] = item.split("=")[1]
		result = ""

		for key in params:
			result += "%s=%s&" % (urllib.quote(key),
								urllib.quote(params[key]))
		result = re.sub(r'&$', '', result)

		if self.csrf:
			self.get_csrf_token(session, self.auth_url)

		if self.csrf_sendname:
			result += "&%s=%s" % (self.csrf_sendname, self.csrf_value)
		else:
			result += "&%s=%s" % (self.csrf_name, self.csrf_value)
		response = session.post( self.auth_url,
								headers=self.headers,
								data=result,
								cookies=session.cookies)
		if self.auth_success:
			if re.findall(r"%s" % str(self.auth_success), response.text) == []:
				sys.exit("ERROR: HTTP authentication failed")
			else:
				print("INFO: authentication successful")
				

	def failure_check(self):
		"""
		Check if test is failed and if it is false negative/positive
		"""

		if self.detect_type == "status_code":
			if  int(self.status_code) != int(self.actual_status_code):
				self.failed = True
				if  int(self.status_code) == 403:
					self.false_negative = True
					self.false_positive = False
				else:
					self.false_positive = True
					self.false_negative = False
			else:
				self.failed = False
				self.false_negative = False
				self.false_positive = False
		elif self.detect_type == "pattern":
			self.pattern_found = self.response.find(self.pattern)
			if self.pattern_found == -1:
				self.failed = True
				if int(self.status_code) == 403:
					self.false_negative = True
					self.false_positive = False
				else:
					self.false_positive = True
					self.false_negative = False
			else:
				self.failed = False
				self.false_negative = False
				self.false_positive = False
		elif self.detect_type == "regex":
			self.pattern_found = re.findall(r"%s" % self.pattern, self.response)
			if self.pattern_found == []:
				self.failed = True
				if int(self.status_code) == 403:
					self.false_negative = True
					self.false_positive = False
				else:
					self.false_positive = True
					self.false_negative = False
			else:
				self.failed = False
				self.false_negative = False
				self.false_positive = False
		else:
			sys.exit("ERROR: wrong pattern type for blocked page")

	def health_check(self, session):
		try:
			response = session.get(
				self.uri.split("?")[0],
				headers={"User-Agent":"Mozilla/5.0 Windows NT 6.3; Win64; x64 AppleWebKit/537.36 KHTML, like Gecko Chrome/44.0.2403.107 Safari/537.36"},
				cookies=session.cookies)
			if ((self.detect_type == "status_code" and int(response.status_code) == 403)
				or (self.detect_type == "pattern" and response.response.find(response.pattern) != -1)
				or (self.detect_type == "regex" and re.findall(r"%s" % response.pattern, response.response) != [])):
				print("WARNING: Application health-check failed (are we blocked?)")
		except:
			print("ERROR: Can't send request to server (are we blocked?)")


def parse_cli_arguments():
	"""
	CLI argument parser
	"""

	parser = argparse.ArgumentParser(description='Waf Testing Tool')
	parser.add_argument('-f', '--folder',
		dest='path',
		default='./attacks',
		help='Path to folder containing attacks samples',
		required=True)
	parser.add_argument('-u', '--url',
		dest='url',
		help='Set WAF address, e.g.http://127.0.0.1/',
		required=True)
	parser.add_argument('-a', '--useragent',
		dest='ua',
		help='Set User-Agent header value')
	parser.add_argument('-c', '--cookie',
		dest='cookie',
		help='Set Cookies informat key1=value1,key2=value2')
	parser.add_argument('-o', '--output',
		dest='output',
		default='report.html',
		help='Output file (default: report.html)')
	parser.add_argument('-t', '--type',
		dest='type',
		default='status_code',
		help=('Detect blocked page based on HTTP response code,'
				'pattern or regular expression (default: status_code)'),
		choices=["status_code", "pattern", "regex"])
	parser.add_argument('-p', '--pattern',
		dest='pattern',
		help='Detect blocked page based on status code or pattern')
	parser.add_argument('--all',
		dest='all',
		action='store_true',
		help='Include passed attack to report')
	parser.add_argument('--auth',
		dest='auth',
		choices=["basic","digest","http"],
		help='Enable authentication')
	parser.add_argument('--auth-url',
		dest='auth_url',
		help='Set url for authentication')
	parser.add_argument('--auth-params',
		dest='auth_params',
		help='Set authentication parameters in format key1=value1,key2=value2. E.g. for basic and digest auth username should be set as login, password as password: login=john,password=pwd123')
	parser.add_argument('--auth-success',
		dest='auth_success',
		help='Regex pattern to find in response and detect if HTTP auth was successful.')
	parser.add_argument('--csrf',
		dest='csrf',
		action='store_true',
		help='Get CSRF-token from response (body, header or cookie)')
	parser.add_argument('--csrf-name',
		dest='csrf_name',
		help='Param name, that should be found in response')
	parser.add_argument('--csrf-sendname',
		dest='csrf_sendname',
		help='Set param name, that is placed in POST-requests if it deffers with csrf-name')
	parser.add_argument('--health',
		dest='health',
		default=10,
		type=int,
		help='Check server availability frequency (default: 10, disable: 0)')
	parser.add_argument('--report-template',
		dest='report_template',
		default="report.jinja2",
		help='Set jinja2 report template')
	parser.add_argument('--threads',
		dest='threads',
		default=1,
		type=int,
		help='Set threads number (default: 1)')
	result = parser.parse_args()

	if result.type == "status_code" and result.pattern:
		parser.print_help()
		sys.exit("ERROR: invalid option PATTERN for status_code type.")

	if result.csrf == True and not result.csrf_name:
		parser.print_help()
		sys.exit("ERROR: CSRF-token name is not set")

	if result.auth == "http" and not result.auth_url:
		parser.print_help()
		sys.exit("ERROR: Auth URL is not specified")

	if result.auth and not result.auth_params:
		parser.print_help()
		sys.exit("ERROR: Auth parameters are not specified")

	return result

def list_files(folder):
	"""
	get all file names from specified catalog
	"""

	result = list()
	for root, dirs, files in os.walk("%s" % folder, topdown=False):
		for name in files:
			result.append(os.path.join(root, name))

	if result == []:
		sys.exit("ERROR: no files discovered")
	else:
		return sorted(result)

def load_attacks(file):
	"""
	parse specified file to get attacks list

	params:
	file  file name with payloads
	"""

	result = list()

	try:
		for attack in json.loads(open(file,'r').read()):
			result.append(attack)
	except IOError:
		sys.exit("ERROR: opening the file %s" % file)
	except ValueError as err:
		sys.exit("ERROR: processing file %s: %s" % (file, err))
	return result

def pretty_raw_request(response):
	"""
	form pretty looking raw request based on sent data

	params:
	response  requests object sent to waf or application
	"""

	result = response.request.method + " " + response.request.path_url + " HTTP/1.1\n"
	result += "Host: %s\n" % response.url.split('/')[2]

	for key,value in response.request.headers.items():
		if key != "Connection":
			result += "%s: %s\n" % (key,value)

	result += "Connection: %s\n" % response.request.headers["Connection"]

	if response.request.body != None:
		result += "\n%s" % response.request.body
	else:
		result += "\n"
	return result

def process_attack(opts):
	"""
	send attack to server
	update tqdm progress bar
	store attack object in sharedattacks

	params:
	opts  list with foolowing parameters:
	[0]   single attack from list
	[1]   parsed Url object
	[2]   requests object with current session
	[3]   parsed CLI arguments
	[4]   list shared between processes to handle test results
	[5]   name of file with payloads
	[6]   tqdm progress bar
	[7]   tqdm status (enabled/disabled)
	"""

	item = opts[0]
	url = opts[1]
	session = opts[2]
	args = opts[3]
	sharedattacks = opts[4]
	attack = Attack(item)
	attack.file = opts[5]
	pbar = opts[6]
	tqdm_enabled = opts[7]
	attack.auth = args.auth
	attack.auth_url = args.auth_url
	attack.auth_params = args.auth_params
	attack.csrf = args.csrf
	attack.csrf_name = args.csrf_name
	attack.csrf_sendname = args.csrf_sendname
	attack.detect_type = args.type
	attack.pattern = args.pattern
	attack.uri = "%s://%s:%s/%s" % (url.protocol, url.host, url.port, url.path)

	if tqdm_enabled == 1:
		pbar.update()

	if args.cookie:
		attack.headers["Cookie"] = args.cookie.replace(",","; ")

	if args.ua:
		attack.headers["User-Agent"] = args.ua

	if args.health != 0:
		if random.randint(1,args.health) == 5:
			attack.health_check(session)

	try:
		attack.send(url, session)
	except exceptions.ConnectionError as err:
		print("WARNING: attack send error: %s " % err)
		return None

	attack.failure_check()
	sharedattacks.append(attack.__dict__)

def count_failed(attacks):
	"""
	count failed, false_negative and false_positive attacks

	params:
	attacks  list with results of testing
	"""

	count = {"_total": {"total":0,"fn":0,"fp":0}}
	for attack in attacks:
		try:
			count[attack["file"]]["total"] += 1
			count[attack["file"]]["fn"] += attack["false_negative"]
			count[attack["file"]]["fp"] += attack["false_positive"]
			count["_total"]["total"] += 1
			count["_total"]["fn"] += attack["false_negative"]
			count["_total"]["fp"] += attack["false_positive"]
		except:
			count[attack["file"]] = {"total":0,"fn":0,"fp":0}
			count[attack["file"]]["total"] += 1
			count[attack["file"]]["fn"] += attack["false_negative"]
			count[attack["file"]]["fp"] += attack["false_positive"]
			count["_total"]["total"] += 1
			count["_total"]["fn"] += attack["false_negative"]
			count["_total"]["fp"] += attack["false_positive"]
	return count

def generate_report(attacks,args):
	"""
	generate report based on report.jinja2 template

	args     parsed CLI arguments
	attacks  list with test results
	"""

	count = count_failed(attacks)
	if attacks == []:
		sys.exit("\nERROR: there is no data for report (zero attacks were processed)")

	template = Template(open(args.report_template,'r').read())
	report = template.render(host=attacks[0]["host"],
							protocol=attacks[0]["protocol"],
							count=OrderedDict(count),
							attacks=attacks,
							all=args.all,
							date=time.strftime("%d %B %Y %H:%M:%S"))

	try:
		with codecs.open(args.output,'w','utf-8') as output:
			output.write(report)
	except:
		print("\nERROR: can't write to file %s" % args.output)

def initial_auth_http(args, session):
	"""
	perform http auth (before attack processing)

	params:
	args     parsed CLI arguments
	session  current requests session
	"""

	attack = Attack({"body": None, "description": None, "url": None, "status_code": 403, "id": "AUTH", "headers": {"Connection": "keep-alive", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 Windows NT 6.3; Win64; x64 AppleWebKit/537.36 KHTML, like Gecko Chrome/44.0.2403.107 Safari/537.36"}, "method": "POST", "payload": ""})
	attack.detect_type = args.type
	attack.pattern = args.pattern
	attack.csrf = args.csrf
	attack.csrf_name = args.csrf_name
	attack.csrf_sendname = args.csrf_sendname
	attack.auth = args.auth
	attack.auth_url = args.auth_url
	attack.auth_params = args.auth_params
	if args.auth_success:
		attack.auth_success = args.auth_success
	attack.auth_http(session)

def main_function(tqdm_enabled):
	"""
	main process to handle attacks

	params:
	tqdm_enabled  tqdm status (enabled/disabled)
	"""

	args = parse_cli_arguments()
	filelist = sorted(list_files(args.path))
	url = Url()
	url.parse(args.url)
	session = WttManager()
	session = Session()

	if args.auth == "http":
		initial_auth_http(args, session)

	pool = mp.Pool(processes=args.threads)
	wttmanager = Manager()
	sharedattacks = manager.list()

	for filename in filelist:
		attacks = load_attacks(filename)
		pbar = wttmanager.Bar()
		if tqdm_enabled == 1:
			pbar.set(len(attacks),
					filename,
					filelist.index(filename))
		else:
			print("Processing file: %s" % filename)
		process_attack([attacks[0],url,session,args,sharedattacks,filename,pbar,tqdm_enabled])
		pool.map(   process_attack,
					zip(attacks,
						repeat(url),
						repeat(session),
						repeat(args),
						repeat(sharedattacks),
						repeat(filename),
						repeat(pbar),
						repeat(tqdm_enabled)))

	print("\nGenerating report...\t")
	generate_report(sorted(sharedattacks, key=lambda k: k["id"]), args)
	print("ok")

if __name__ == '__main__':
	mp.freeze_support()
	manager = mp.Manager()
	packages.urllib3.disable_warnings(InsecureRequestWarning)
	main_function(tqdm_enabled)