import re,os,socket,ssl,httplib,requests
from OpenSSL import crypto

from eventlet import GreenPool,Timeout
from urlparse import urlparse
from random import choice
from Common import *
from Bing import Bing
from Webby import Webby
from DNSHandler import DNSHandler

requests.packages.urllib3.disable_warnings()

class Classifier:
    def __init__(self,scopeObj,startingWebbies,useragents,threadCount,verbosity,nolookups,bing_key,resolvers=[]):
        self.scopeObj = scopeObj
        self.resolvers = resolvers
        self.useragent = choice(useragents)
        self.toClassify = startingWebbies
        self.storage = set()
        self.webbyHistory = set()
        self.webbyPool = GreenPool(size=threadCount)
        self.DNSPool = GreenPool(size=threadCount)
        self.maxRedirect = 4
        self.maxWait = 15
        self.verbosity = verbosity
        self.threadCount = threadCount
        self.nolookups = nolookups

        self.bing_key = bing_key
        self.bing_vname_history = set()
        self.bing_ip_history = set()

        self.ALTNAME_EXTENSION = 2

    def reinit(self):
        self.webbyPool = GreenPool(size=self.threadCount)
        self.DNSPool = GreenPool(size=self.threadCount)

    def fetch(self,webby):
        with Timeout(self.maxWait,False):
            paths = set("/")
            pathHistory = set()
            pathCount = 0
            headers = {"User-Agent":self.useragent}
            host = webby.hostname if webby.hostname else webby.ip
            while len(paths) > 0 and pathCount < self.maxRedirect:
                path = paths.pop()
                pathCount +=1
                requestSent = False
                try:
                    conn = None
                    response = None
                    if webby.ssl == None:
                        try:
                            conn = httplib.HTTPSConnection(host,webby.port,timeout=3,context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))
                            conn.request("GET",path,headers=headers)
                            webby.ssl = True
                            requestSent = True
                        except ssl.SSLError:
                            conn = httplib.HTTPConnection(host,webby.port,timeout=3)
                            conn.request("GET",path,headers=headers)
                            webby.ssl = False
                            requestSent = True
                    elif not webby.ssl:
                        conn = httplib.HTTPConnection(host,webby.port,timeout=3)
                        conn.request("GET",path,headers=headers)
                        requestSent = True
                    else:
                        conn = httplib.HTTPSConnection(host,webby.port,timeout=3,context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))
                        conn.request("GET",path,headers=headers)
                        requestSent = True
                except socket.error,ex:
                    #failed to connect to webby
                    print_error("Socket Failure %s(%s):%s %s" % (webby.ip,webby.hostname,webby.port,ex))
                    webby.success = False
                    webby.errormsg = ex
                    self.storage.add(webby)
                if requestSent:
                    try:
                        response = conn.getresponse()
                        headers = dict(response.getheaders())
                        data = response.read()
                        titleRE = re.compile(r'< *title *>(?P<title>.*?)< */title *>',re.I)

                        webby.code = response.status
                        webby.url = "http://" if not webby.ssl else "https://"
                        webby.url += webby.hostname if webby.hostname else webby.ip
                        webby.url +=":%s" % webby.port if webby.port else ""
                        webby.url += path if path.startswith('/') else '/'+path

                        webby.lastResponse = data

                        if 'server' in headers:
                            webby.banner = headers['server']
                        if 'location' in headers:
                            urlObj = urlparse(headers['location'])
                            if urlObj.netloc:
                                if urlObj.netloc.count(':') > 0:
                                    host,port = urlObj.netloc.split(':')
                                else:
                                    host = urlObj.netloc
                                    if urlObj.scheme and urlObj.scheme == "https":
                                        port = "443"
                                    elif urlObj.scheme and urlObj.scheme == "http":
                                        port = "80"
                                    else: # catch //foo.com/ redirects that use current scheme
                                        port = webby.port
                                if (host == webby.hostname or host == webby.ip) and port == webby.port:
                                    paths.add(urlObj.path if urlObj.path.startswith('/') else '/'+urlObj.path)
                                else:
                                    webby.redirect = urlObj.geturl()
                                    if re.search('[A-Za-z]',host):
                                        newWebby = Webby(ip="",hostname=host,port=port)
                                    else:
                                        newWebby = Webby(ip=host,hostname="",port=port)
                                    if newWebby not in self.webbyHistory and newWebby not in self.toClassify:
                                        self.toClassify.add(newWebby)
                                    self.storage.add(webby)
                            else:
                                paths.add(urlObj.path if urlObj.path.startswith('/') else '/'+urlObj.path)
                                if pathCount == (self.maxRedirect-1): #infinite redirect
                                    self.storage.add(webby)
                        else:
                            if re.search('< *FORM',data,re.I):
                                webby.forms = True
                            if re.search('input.*type\s*=\s*(?:\'|"| *)password',data,re.I):
                                webby.login = True
                            try:
                                webby.title = titleRE.search(data.replace('\n',' ')).group('title').strip()
                            except:
                                webby.title = "NO_TITLE"

                            self.storage.add(webby)

                        if webby.ssl:
                            pem_cert = ssl.get_server_certificate((webby.ip,int(webby.port)))
                            cert = crypto.load_certificate(crypto.FILETYPE_PEM,pem_cert)
                            for k,v in cert.get_subject().get_components():
                                if k == "CN":
                                    if re.search('[A-Za-z]',v):
                                        newWebby = Webby(ip="",hostname=v,port=webby.port)
                                        if newWebby not in self.webbyHistory and newWebby not in self.toClassify:
                                            self.toClassify.add(newWebby)
                            dns_names = filter(lambda x: x.count('DNS:'),str(cert.get_extension(self.ALTNAME_EXTENSION)).split(','))
                            dns_names = map(lambda x: str(x).split(':',1)[1],dns_names)
                            for vname in dns_names:
                                newWebby = Webby(ip="",hostname=vname,port=webby.port)
                                if newWebby not in self.webbyHistory and newWebby not in self.toClassify:
                                    self.toClassify.add(newWebby)

                    except Exception,ex:
                        #connection timed out
                        print_error("Timeout Error %s(%s):%s %s" % (webby.ip,webby.hostname,webby.port,ex))
                        webby.success = False
                        webby.errormsg = ex
                        self.storage.add(webby)

    def enumerate(self,webby):
        myDNSHandler = DNSHandler()

        if len(self.resolvers) > 0:
            myDNSHandler.nameservers = self.resolvers
        if webby.hostname and not webby.ip:
            for ip in myDNSHandler.resolveHostname(webby.hostname):
                if self.scopeObj.inScope(ip):
                    webby = Webby(ip,webby.hostname,webby.port,firstrun=False)
                    if webby not in self.storage and webby not in self.toClassify:
                        self.toClassify.add(webby)
                else:
                    print_warning("excluding webby %s(%s):%s not in scope." % (ip,webby.hostname,webby.port))

        elif webby.ip and not webby.hostname:
            if self.scopeObj.inScope(webby.ip):
                for hostname in myDNSHandler.resolveIP(webby.ip):
                    nwebby = Webby(webby.ip,hostname,webby.port,firstrun=False)
                    if nwebby not in self.storage and nwebby not in self.toClassify:
                        self.toClassify.add(nwebby)
                nwebby =Webby(webby.ip,"",webby.port,firstrun=False)
                if nwebby not in self.storage and nwebby not in self.toClassify:
                    self.toClassify.add(nwebby)
            else:
                print_warning("excluding webby %s(%s):%s not in scope." % (webby.ip,webby.hostname,webby.port))
        else:
            if self.scopeObj.inScope(webby.ip) and \
                webby.hostname in myDNSHandler.resolveIP(webby.ip):
                    webby.firstrun=False
                    self.toClassify.add(webby)

        if self.bing_key:
            try:
                xbing = Bing(self.bing_key)
                if webby.hostname and webby.hostname not in self.bing_vname_history:
                    if self.verbosity:
                        print_info("searching bing for hostname '{vname}'".format(vname=webby.hostname))
                    xbing.search_domain(webby.hostname)
                    self.bing_vname_history.add(webby.hostname)
                if webby.ip and webby.ip not in self.bing_ip_history:
                    if self.verbosity:
                        print_info("searching bing for ip '{ip}'".format(ip=webby.ip))
                    xbing.search_ip(webby.ip)
                    self.bing_ip_history.add(webby.ip)
                for host_port_combo in xbing.uniq_hosts:
                    hostid,port = host_port_combo.split(':')
                    ip = hostname= ""
                    if re.search('^[0-9]{1,3}(\.[0-9]{1,3}){3}$',hostid):
                        ip = hostid
                        hostname = ""
                    else:
                        hostname = hostid
                        ip = ""
                    nwebby = Webby(ip=ip,hostname=hostname,port=port)
                    if nwebby not in self.storage and nwebby not in self.toClassify:
                        self.toClassify.add(nwebby)
            except Exception,ex:
                print_error("Bing search failed:{etype} {msg}".format(etype=type(ex),msg=str(ex)))

    def run(self):
        while len(self.toClassify) > 0:
            webby = self.toClassify.pop()
            if webby.firstrun and not self.nolookups:
                if self.verbosity > 0:
                    print_info("enumerating webby %s(%s):%s" % (webby.ip,webby.hostname,webby.port))
                self.DNSPool.spawn_n(self.enumerate,webby)
            elif webby not in self.storage and webby not in self.webbyHistory:
                print_success("launching webby %s(%s):%s" % (webby.ip,webby.hostname,webby.port))
                self.webbyHistory.add(webby)
                self.webbyPool.spawn_n(self.fetch,webby)
            if not len(self.toClassify):
                self.webbyPool.waitall()
                self.DNSPool.waitall()
