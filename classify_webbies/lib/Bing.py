import requests,argparse,sys
from urlparse import urlparse
from base64 import b64encode

class Bing:
    def __init__(self,apikey):
        self.key = apikey
        self.headers = {
                        "Authorization": "Basic {ekey}".format(ekey=b64encode(":"+self.key)),
                        "User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0"
                        }
        self.parameters = {
                    "$format":"json",
                    "$top":50,
                    }
        self.uniq_hosts = set()
        self.uniq_urls = set()
        self.url = "https://api.datamarket.azure.com/Bing/Search/Web"

    def __process(self,request):
        for i in request['d']['results']:
            url = str(i['Url'].encode('ascii','ignore'))
            self.uniq_urls.add(url)
            up = urlparse(url)
            x = up.netloc
            if not x.count(':'):
                if up.scheme == "https":
                    x+=":443"
                else:
                    x+=":80"

            self.uniq_hosts.add(x)
        if len(request['d']['results']) < self.parameters['$top']:
            return False
        else:
            return True

    def search(self,query,pages=3):
        params = {
            "Query":query,
            "$skip":0
        }
        params.update(self.parameters)
        for _ in xrange(pages):
            params["$skip"] = self.parameters["$top"] * _
            r = requests.get(self.url,params=params,headers=self.headers,verify=False).json()
            if not self.__process(r):
                break

    def search_domain(self,domain,pages=3):
        query = "'domain:{domain}'".format(domain=domain)
        self.search(query,pages)

    def search_ip(self,ip,pages=3):
        query = "'ip:{ip}'".format(ip=ip)
        self.search(query,pages)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Bing.py',description='bing search')
    parser.add_argument("-k","--key",help="API key",required=True)
    parser.add_argument("-d","--domain",help="domain lookup")
    parser.add_argument("-i","--ip",help="ip lookup")

    if len(sys.argv) <2 :
        parser.print_help()
        sys.exit(0)

    args=parser.parse_args()

    b = Bing(args.key)
    if args.ip:
        b.search_ip(args.ip)
    if args.domain:
        b.search_domain(args.domain)


    print "unique hosts"
    for x in b.uniq_hosts:
        print x
    print ""

    print "unique urls"
    for x in b.uniq_urls:
        print x
