import dns.resolver,re

class DNSHandler:
    def __init__(self,nameservers=[],timeout=2):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = 3
        self.ipRE = re.compile('IN A (?P<IP>.*?)\n',re.S)
        self.hostnameHistory = {}
        self.reverseHistory = {}
        if nameservers:
            self.resolver.nameservers = nameservers

    def resolveHostname(self,host):
        if host not in self.hostnameHistory:
            try:
                ips = self.ipRE.findall(str(self.resolver.query(host).response))
                self.hostnameHistory[host] = set(ips)
            except:
                try:
                    self.hostnameHistory[host] =  set([socket.gethostbyname(host)])
                except:
                    self.hostnameHistory[host] = set() #fail lookup

        return self.hostnameHistory[host]

    def resolveIP(self,host):
        if host not in self.reverseHistory:
            ip = str(host).split('.')
            if ip[3] == '255' or ip[3]=='0': #not valid IP
                self.reverseHistory[host] = set()
            else:
                ip.reverse()
                ip ="%s.in-addr.arpa" % (".".join(ip))
                try:
                    hostnames = self.resolver.query(ip,"PTR")
                    self.reverseHistory[host] = set(map(lambda x: str(x).rstrip('.'),hostnames))
                except:
                    try:
                        self.reverseHistory[host] = set([socket.gethostbyaddr(host)[0]])
                    except:
                        self.reverseHistory[host]= set() #fail lookup
        return self.reverseHistory[host]
