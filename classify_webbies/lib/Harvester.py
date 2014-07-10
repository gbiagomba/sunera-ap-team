import re,os
import xml.etree.ElementTree as ET
from Webby import Webby

class Harvester:
    def __init__(self):
        self.webbies = set()

    def harvestNessusDir(self,nessusDir):
        if not nessusDir.endswith('/'):
          nessusDir = nessusDir + '/'
        for xfile in os.listdir(nessusDir):
            if xfile.endswith(".nessus"):
                self.harvestNessus(nessusDir+xfile)

    def harvestNessus(self,nessusFile):
        tree = ET.parse(nessusFile)
        root = tree.getroot()

        for host in root.iter('ReportHost'):
            try:
                hostname = host.find('./HostProperties/*[@name="host-fqdn"]').text
            except AttributeError:
                hostname = ""
            try:
                ip = host.find('./HostProperties/*[@name="host-ip"]').text
            except AttributeError:
                ip = host.attrib['name']

            for tcp_item in host.findall('./ReportItem[@pluginID="10335"]'):
                if re.search(r'(www|htt|web)',tcp_item.attrib['svc_name'],re.I):
                    self.webbies.add(Webby(ip,hostname,tcp_item.attrib['port']))
            svc_names = ['www','https?','http?','http_proxy','http','https']
            for svc_name in svc_names:
                for www in host.findall('./ReportItem[@svc_name="%s"]' % svc_name):
                    self.webbies.add(Webby(ip,hostname,www.attrib['port']))

    def harvestGnmapDir(self,gnmapDir):
        if not gnmapDir.endswith('/'):
          gnmapDir = gnmapDir + '/'
        for xfile in os.listdir(gnmapDir):
            if xfile.endswith(".gnmap"):
                self.harvestGnmap(gnmapDir+xfile)

    def harvestGnmap(self,gnmapFile):
        lineRE = re.compile(r'Host:\s+(?P<host>.*?)\s+.*?Ports:\s+(?P<ports>.*?)$')
        portsRE = re.compile(r'(?P<port>[0-9]+)/+open/+tcp/+.*?http.*?(?:,|$)',re.I)

        for line in filter(None,open(gnmapFile).read().split('\n')):
            x = lineRE.search(line)
            if x:
                openPorts = portsRE.findall(x.group('ports'))
                host = x.group('host')
                if len(openPorts) > 0:
                    if re.search('[A-Za-z]',host):
                            hostname = host
                            ip = ""
                    else:
                            hostname = ""
                            ip = hostname
                    for port  in openPorts:
                            self.webbies.add(Webby(ip,hostname,port))
        return webbies

    def harvestIL(self,ILfile):
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

            if re.search('[a-zA-Z]',host):
                self.webbies.add(Webby(ip="",hostname=host,port=port))
            else:
                self.webbies.add(Webby(ip=host,hostname="",port=port))
