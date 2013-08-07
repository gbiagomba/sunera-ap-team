#!/usr/bin/python
#    Copyright (C) 2013 Sunera, LLC
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#    #####################################################################
#    Author:            Nick Newsom   
#    Blog:              http://security.sunera.com/
#
#    Program Name:      classify.webbies.py
#    Purpose:           Enumerate and screenshot web services
#    Version:           3.1
#    Code Repo:         http://code.google.com/p/sunera-ap-team/

import sys,re,httplib,socket,signal,argparse,time,os,subprocess,shlex
from netaddr import IPNetwork,IPAddress
from random import choice
from threading import *

#debug
import cPickle as pickle
import copy

#anaylze
from difflib import SequenceMatcher
import pygraphviz as PG


class Webby:
        def __init__(self,ip,hostname,port):
                self.ip = ip
                self.hostname = hostname
                self.port = port
                self.desc = ""
                self.responses = {}
                self.banner = ""
                self.code = None
                self.forms = False
                self.login = False
                self.ssl = True
                self.url = None
        def addPathResponse(self,path,response,forms,login,banner,statusCode):
                self.responses[path] = response
                self.forms = forms
                self.login = login
                self.code = statusCode
                self.banner = banner
	def getPathContent(self):
		result = ("","")
		for path,response in self.responses.items():
			if len(response) > len(result):
				result = (path,response)
		return result

	def getID(self):
		path,content = self.getPathContent()
		ID = ""
		if self.hostname != "" :
			ID = "%s:%s/%s" % ( self.hostname,self.port,path )
		else:
			ID = "%s:%s/%s" % ( self.ip,self.port,path )
		return ID.replace('//','/')

        def toCSV(self):
                #ip,name,port,protocol,service,banner,notes
                if re.search(r'30[0-9]',str(self.code)):
                        notes = "%d|%s " % (self.code,self.desc)
                elif not self.code:
                        notes = "FAILED_TO_CLASSIFY"
                else:
                        notes = "%s%s%s%s%s" % (self.code, \
                                                "|"+self.desc if self.desc != "" else "|", \
                                                "|forms" if self.forms else "|", \
                                                "|login" if self.login else "|",\
						"|"+self.url if self.url and self.code == 200 else "|")
                return  "%s,%s,%s,TCP,%s,%s,%s" % ( \
                                                        self.ip,\
                                                        self.hostname, \
                                                        self.port, \
                                                        "https" if self.ssl else "http", \
                                                        self.banner, \
                                                        notes \
                                                        )
        def debugPrint(self):
                print "%s:%s forms:%s login:%s ssl:%s" % (self.ip,self.port,self.forms,self.login,self.ssl)
                print "Desc: %s\tURL: %s\tcode: %s" % (self.desc,self.url,self.code)
                try:
                        print "filename: %s" % (re.sub('[\W]+','.',self.url))
                except:
                        print "failed filename"
                for path,response in self.responses.iteritems():
                        print "\tpath: '%s'" % path

class color:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELO = '\033[93m'
        RED = '\033[91m'
        OPTIMUM = '\033[7m'
        NOPTIMUM = '\033[2m'
        ENDC = '\033[0m'

class Classifier:
	def __init__(self,scope,startingWebbies,timeout,retries,threadCount,maxPath,useragents,verbosity):
		self.toClassify = startingWebbies
		self.history = {}
		self.storage = {}
		self.scope = scope
		self.timeout = timeout
		self.retries = retries
		self.threadCount = threadCount
		self.threads = []
		self.lock = Semaphore(value=1)
		self.lookup = {}
		self.maxPath = maxPath
		self.reverse = {}
		self.verbosity = verbosity
		self.control = BoundedSemaphore(value=self.threadCount)
		self.useragent = choice(useragents)
		if self.verbosity > 0:
			sys.stderr.write("[I] Crawler UA set to' %s'\n" % self.useragent)

	def inScope(self,host):
		retries = self.retries
		hostname = ""
		ip = ""
		result = False	
		if host.count(':') > 0:
			host = host.split(':')[0]
		if re.search('[a-zA-Z]+',host):
			if host not in self.lookup:
				while retries > 0:
					try:
						ip = socket.gethostbyname(host) 
						result=True
						break
					except socket.gaierror:
						sys.stderr.write("%s[*] Failed to resolve %s. skipping host.\n%s"% (color.RED,host,color.ENDC))
						ip = ""
						break
					except:
						sys.stderr.write("%s[*] Resource busy..waiting...%s\n" %(color.YELO,color.ENDC))
						time.sleep(3)
						retries-=1
                                self.lookup[host] = ip
			ip = self.lookup[host]
			hostname = host
		else:
			if host not in self.reverse:
				try:
					hostname = socket.gethostbyaddr(host)[0]
				except:
					hostname = ""
				self.reverse[host] = hostname
			hostname = self.reverse[host]
			ip = host
			result = True
		if result:
			result = False
			for network in self.scope:
				if IPAddress(ip) in network:
					result = True
		return (ip,hostname,result)

	def grabResponse(self,conn,path,key):
		try:
			#headers = {"User-Agent": self.useragent}
			if self.verbosity > 1:
				print "%s: grabbing response to path %s" % (key,path)
			#conn.request("GET",path,headers=headers)
			conn.request("GET",path)
			response = conn.getresponse()
			return response
		except socket.timeout as t:
			if self.verbosity > 1:
				print "%s: timeout" % (key)
			return None
		except:
			if self.verbosity > 1:
				print "%s: failed" % key
			return "failed"

	def enumerate(self,host,port,record):
		ssl = True
		success = True
		paths = ["/"]
		pathHistory = []

		self.history[host].add(port)
		key = "%s:%s" % (host,port)
		while len(paths) > 0 and len(pathHistory) < self.maxPath:
			success=False
			path = paths.pop()
			pathHistory.append(path)
			if ssl:
				if self.verbosity > 1:
					print "%s: attempting https" % key
				for i in xrange(self.retries):
					conn = httplib.HTTPSConnection(host,port,timeout=self.timeout+i)		
					response = self.grabResponse(conn,path,key)
					if response and response=="failed":
						break
					elif response:
						success=True
						break
				if not success:
					ssl = False
			if not ssl:
				if self.verbosity > 1:
					print "%s: attempting http" % key
				for i in xrange(self.retries):
					conn = httplib.HTTPConnection(host,port,timeout=self.timeout+i)		
					response = self.grabResponse(conn,path,key)	
					if response and response=="failed":
						response = None
						break
					if response:
						success=True
						break

			if success:
				if self.verbosity > 1:
					print "%s: enumerating service" % key
				titleRE = re.compile(r'< *title *>(?P<title>.*?)< */title *>',re.I)
				record.ssl = ssl
				headers = dict(response.getheaders())
				form = False
				login = False
				code = response.status	
				banner =""
				data = ""
				if 'server' in headers:
					banner = headers['server']
				if 'location' in headers:
					if re.search('^http',headers['location']):
						lhost = headers['location'].split('/')[2].split(':')[0]
						try:
							path = '/'+headers['location'].split('/',3)[3]
						except IndexError:
							path = '/'
						portRE = re.search(':(?P<port>[0-9]+)/',headers['location'])
						if portRE:
							nport = portRE.group('port')
						elif re.search('https',headers['location']):
							nport = 443
						else:
							nport = 80
						if host == lhost and path not in pathHistory:
							paths.append(path)
						elif self.inScope(lhost)[2]:
							self.lock.acquire()
							if lhost in self.history and nport in self.history[lhost]:
								pass
							elif lhost in self.toClassify and lhost in self.history:
								if nport in self.history[lhost]:
									pass
								else:
									self.toClassify[lhost].add(nport)
							elif lhost in self.toClassify and lhost not in self.history:
								self.toClassify[lhost].add(nport)
							else:
								self.toClassify[lhost] = set()
								self.toClassify[lhost].add(nport)
							self.lock.release()
						else:
							sys.stderr.write("%s[*] %s is out of scope.\n%s"% (color.RED,lhost,color.ENDC))
						record.desc = headers['location']	
					elif headers['location'] not in pathHistory:
						paths.append(headers['location'])
				else:
					try:
						data = response.read()
						if ssl:
							record.url = "https://%s:%s%s" % (host,port,path)
						else:
							record.url = "http://%s:%s%s" % (host,port,path)
					except:
						record.desc = "Failed loading"
					try:
						record.desc = titleRE.search(data.replace('\n',' ')).group('title').strip()
					except:
						record.desc = "NO_TITLE"
					if re.search('< *FORM',data,re.I):
						form = True
					if re.search('input.*type\s*=\s*(?:\'|"| *)password',data,re.I):
						login = True
				record.addPathResponse(path,data,form,login,banner,code)
			else:
				print "%s[!]%s Connection Failed: %s:%s|%s" % (color.RED,color.ENDC,host,port,path)
			self.storage[key] = record
		#in threads, this behaves like thread.exit()
		self.control.release()
		sys.exit()
	
	def run(self):
		while len(self.toClassify) > 0:
			host,ports= self.toClassify.popitem()
			ip,hostname,inScope = self.inScope(host)
			if inScope:
				if host not in self.history:
					self.history[host] = set()
				for port in ports: 
					self.control.acquire()
					if self.verbosity > 0:
						print "%srunning against%s %s:%s" % (color.GREEN,color.ENDC,host,port)
					record = Webby(ip,hostname,port)
					t = Thread(target=self.enumerate, args= (host,port,record))
					t.daemon = True
					self.threads.append(t)
					try:
						t.start()
					except:
						sys.stderr.write("%s[*]start fail. %d active threads%s" % (color.RED,active_count(),color.ENDC))
						self.control.release()
		while len(self.threads) > 0:
			self.threads = [t.join(1) for t in self.threads if t is not None and t.isAlive()]

def signalHandler(signal, frame):
        sys.stderr.write("\n\n[*] Ctrl+C detected. exiting...\n\n")
	if not args.pickle:
		if args.verbosity > 1:
			for key,webby in classifier.storage.iteritems():
				webby.debugPrint()
		sys.stderr.write("\n[*]Writing classifer dump to 'classifier_dump.csv\n")
		sys.stdout = open('classifier_dump.csv','w')
		printCSV(classifier.storage)
        sys.exit(1)

def harvestNBE(nbeFile):
	webbies={}
	for line in filter(None,open(nbeFile).read().split('\n')):
		field = line.split('|')
		ip = field[2]
		service = field[3]
		if re.search("(www|htt|web)",service):
			port = re.search("[0-9]+",service).group(0)
			if ip not in webbies:
				webbies[ip] = set()
				webbies[ip].add(port)
			else:
				webbies[ip].add(port)
	return webbies

def harvestGnmap(gnmapFile):
	lineRE = re.compile(r'Host:\s+(?P<host>.*?)\s+.*?Ports:\s+(?P<ports>.*?)$')
	portsRE = re.compile(r'(?P<port>[0-9]+)/+open/+tcp/+.*?http.*?(?:,|$)',re.I)
	webbies ={}

	for line in filter(None,open(gnmapFile).read().split('\n')):
		x = lineRE.search(line)
		if x:
			openPorts = portsRE.findall(x.group('ports'))
			if len(openPorts) > 0:
				if x.group('host') not in webbies:
					webbies[x.group('host')] = set()
				webbies[x.group('host')] |= set(openPorts)
	return webbies

def harvestIL(ILfile):
	webbies={}
	urlRE =re.compile(r'(?P<proto>.*?)://(?P<host>.*?):(?P<port>[0-9]+)')
	ipportRE = re.compile(r'(?P<host>.*?):(?P<port>[0-9]+)')
	for line in filter(None,open(ILfile).read().split('\n')):
		x = urlRE.search(line)
		if x:
			host = x.group('host')
			port = x.group('port')
		else:
			x = ipportRE.search(line)
			if x:
				host = x.group('host')
				port = x.group('port')
			else:
				print "failed to import '%s'" % line
				host = None
		if host and host not in webbies:
			webbies[host] = set()
			webbies[host].add(port)
		elif host:
			webbies[host].add(port)
	return webbies


def printCSV(storage):
	sys.stderr.write("Saving csv...\n")
	print "IP,NAME,PORT,PROTOCOL,SERVICE,BANNER,NOTES"
	if not args.pickle:
		for key,webby in storage.items():
			print webby.toCSV()

parser = argparse.ArgumentParser(prog='classify.webbies.py',description='enumerate and display detailed information about web listeners')
parser.add_argument("-A","--analyze",help="generate graphs and csv grouped by site similiarity",default=None)
parser.add_argument("-d","--debug",help="saves pickle file of webbies harvested",dest="debug",action="store_true",default=False)
parser.add_argument("-g","--gnmap",help="gnmap input file")
parser.add_argument("-G","--gnmapdir",help="Directory containing gnmap input files")
parser.add_argument("-i","--inputList",help="input file with hosts listed http(s)://ip:port/ or ip:port per line")
parser.add_argument("-n","--nbe",help="NBE input file")
parser.add_argument("-N","--nbedir",help="Directory containing NBE files")
parser.add_argument("-o","--output",help="Output file. Supported types are csv")
parser.add_argument("-p","--maxpaths",help="Max number of redirect paths to attempt per host. Default is 4",default=4)
parser.add_argument("-P","--pickle",help="Load in previous webbies crawl for analysis and/or screenshots",default=None)
parser.add_argument("-r","--retries",type=int,help="number of retries. Default is 3",default=3)
parser.add_argument("-s","--scope",help="Scope file with IP Networks in CIDR format")
parser.add_argument("-S","--screenshotDir",help="enables and specifies screenshot dir. REQUIRES PHANTOMJS",default=None)
parser.add_argument("-t","--timeout",type=int,help="Set base timeout. Default is 2 seconds",default=2)
parser.add_argument("-T","--threads",type=int,help="Set the max number of threads. The classifier will kept it *around* this number",default=5)
parser.add_argument("-u","--useragents",help="specifies file of user-agents to randomly use.",default=None)
parser.add_argument("-v","--verbosity",help="-v for regular output, -vv for debug level",action="count",default=0)
parser.add_argument("-V","--version",action='version',version='%(prog)s 3.1')

if len(sys.argv) < 2:
	parser.print_help()
	sys.exit(0)

args = parser.parse_args()
webbies = {}

if args.useragents:
	useragents = filter(None,open(args.useragents).read().split('\n'))
else:
	useragents = [ \
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)", \
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36", \
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",\
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0",\
	"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",\
	"Mozilla/5.0 (iPad; CPU OS 6_1_3 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B329 Safari/8536.25"]

if not args.pickle:
	scope = None
	if args.scope:
		scopeFile = args.scope
		scope = map(lambda x: IPNetwork(x),filter(None,open(scopeFile).read().split('\n')))

	if args.nbe:
		webbies = dict(webbies.items() + harvestNBE(args.nbe).items())
	elif args.nbedir:
		for xfile in os.listdir(args.nbedir):
			if xfile.endswith(".nbe"):
				webbies = dict(webbies.items() + harvestNBE(args.nbedir+xfile).items())
	if args.gnmap:
		webbies = dict(webbies.items() + harvestGnmap(args.gnmap).items()) 
	if args.gnmapdir:
		for xfile in os.listdir(args.gnmapdir):
			if xfile.endswith(".gnmap"):
				webbies = dict(webbies.items() + harvestGnmap(args.gnmapdir+xfile).items())
		
	if args.inputList:
		webbies = dict(webbies.items() +  harvestIL(args.inputList).items())

	if not scope:
		toResolve = filter(lambda x: re.search('[a-zA-Z]',x),webbies.keys())
		ips = filter(lambda x: re.search('^[\d\.]+$',x),webbies.keys())	
		for name in toResolve:
			try:
				ip = socket.gethostbyname(name)
				ips.append(ip)
			except:
				print "failed to resolve '%s' during scope auto-generation. Excluding" % name
		scope = map(lambda x: IPNetwork(x),ips)


	classifier = Classifier(scope,webbies,args.timeout,args.retries,args.threads,args.maxpaths,useragents,args.verbosity)
	signal.signal(signal.SIGINT,signalHandler)
	classifier.run()

	images = []

	if args.debug:
		with open('debugging.clasifier.p','wb') as fp:
				pickle.dump(copy.deepcopy(classifier.storage),fp)

if args.pickle:
	with open(args.pickle,'rb') as fp:
                storage = pickle.load(fp)
		print "webbies loaded from file '%s'." % args.pickle
else:
	storage = classifier.storage

if args.output:
	sys.stdout = open(args.output,'w')
	printCSV(storage)

if args.analyze:
	sys.stderr.write("Analyzing...") 
	threshold = 0.85
	if not args.pickle:
		sys.stderr.write("pickle file '%s.p' created...\n" % args.analyze)
		with open('%s.p' % args.analyze,'wb') as fp:
			pickle.dump(copy.deepcopy(classifier.storage),fp)

	if not os.path.exists(args.analyze):
		os.makedirs(args.analyze)

	result_groups = []
	for key,webby in storage.items():
		if webby.code:
			content =  webby.getPathContent()
			setToGroup = False
			for group in result_groups:
				matched = 0
				for entryID,entryWebby in group.items():
					compare = SequenceMatcher(None,entryWebby.getPathContent(),content).ratio()
					if compare > threshold:
						matched+=1
				if matched == len(group.items()):
					setToGroup = True
					group[webby.getID()] = webby
			if not setToGroup:
				newGroup = {}
				newGroup[webby.getID()] = webby
				for xkey,xwebby in storage.items():
					if xwebby.code:
						compare = SequenceMatcher(None,xwebby.getPathContent(),content).ratio()
						if compare > threshold and xwebby.getID() != webby.getID():
							newGroup[xwebby.getID()] = xwebby
				result_groups.append(newGroup)

	sys.stderr.write("%d unique groups..." % len(result_groups))
	overviewGraph = PG.AGraph(directed=True)
	i=0
	for group in result_groups:
		i+=1
		overviewGraph.add_node("Group %d" % i)
		n = overviewGraph.get_node("Group %d" % i)
		n.attr['color'] =  "#%s" % (''.join(choice('abcedf0123456789') for x in range(6)))
		n.attr['style'] = 'filled'
		n.attr['height'] = (len(group) * .25)
		n.attr['width'] = (len(group) * .25)
		n.attr['fontsize'] = 20.0

	overviewGraph.layout(prog='circo')
	overviewGraph.draw('%s/%s.ps' % (args.analyze,"overviewGraph"), prog='circo')

	masterGraph = PG.AGraph(directed=True, strict=True)
	graph = PG.AGraph(directored=True, strict=True)
	i=0
	for group in result_groups:
		i+=1
		gID = "group%s" % i
		graph = PG.AGraph(directored=True, strict=True,name=gID)
		for url,webby in group.iteritems():
			# no switch cases -_-
			wcolor = 'Grey'
			if re.search("30[0-9]",str(webby.code)):
				wcolor = 'Green'
			if re.search("40[0-9]",str(webby.code)):
				wcolor = 'Blue'
			if re.search("50[0-9]",str(webby.code)):
				wcolor = 'Red'
			graph.add_edge("Group %d" % i,url)
			if wcolor:
				n.attr['color'] = wcolor
				n.attr['style'] = 'filled' 
				n = graph.get_node(url)

			masterGraph.add_edge("Group %d" % i,url)
			n = masterGraph.get_node(url)
			n.attr['color'] = wcolor
			n.attr['style'] = 'filled' 
		graph.layout(prog='circo')
		graph.draw('%s/%s.ps' % (args.analyze,gID), prog='circo')
		f = open("%s/%s.csv" % (args.analyze,gID),'w') 
		for url,webby in group.items():
			f.write("%s://%s\n" % ("https" if webby.ssl else "http", url))
		f.close()
	masterGraph.layout(prog='circo')
	masterGraph.draw('%s/%s.ps' % (args.analyze,"masterGraph"), prog='circo')
	sys.stderr.write("...finished.\n")

if args.screenshotDir:
	sys.stderr.write("%sGathering screenshots...%s\n" % (color.BLUE,color.ENDC))
	if not os.path.exists(args.screenshotDir):
		os.makedirs(args.screenshotDir)
	ua = choice(useragents)
	if args.verbosity > 0:
		sys.stderr.write("[I] Screenshot UA set to '%s'\n" % ua)
	for key,webby in storage.items():
		if webby.code==200 and webby.url:
			filename = re.sub('[\W]+','.',webby.url)
			if filename.endswith('.'):
				filename+="png"
			else:
				filename+=".png"
			if args.verbosity > 1:
				sys.stderr.write("%sSaving file:%s%s\n" % (color.BLUE,color.ENDC,filename))
			command = "phantomjs --ignore-ssl-errors=yes %s/screenshot.js \"%s\" %s %s" % \
				(os.path.dirname(os.path.realpath(__file__)),ua,webby.url,args.screenshotDir+'/'+filename)
			proc = subprocess.Popen(shlex.split(command))
			stdout,stderr =  proc.communicate()
			if stderr:
				print stderr
