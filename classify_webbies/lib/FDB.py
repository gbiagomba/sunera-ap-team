from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from gevent import spawn

from urlparse import urljoin,urlparse
from random import choice
from datetime import datetime
from requests import Session
from Queue import Queue
from time import sleep
from requests.adapters import HTTPAdapter
import sys,string,argparse,re,timeit,gzip

from Common import *
from Probe import *
from NotFoundHandler import *

class FDB:
    def __init__(self,host,wordlist,extensions,threads,verbosity):
        self.PROBE_MISSING_COUNT = 4
        self.MAX_TIME = 60
        self.MAX_FAIL = 30
        self.MAX_RETRY = 3
        self.FATAL = 999
        self.FAILS = 0
        self.POOL_CON = threads * 2
        self.POOL_MAX = threads * 3
        self.INTERVAL_S = 60

        self.host = ""
        self.total = 0
        self.wordlist = set()
        self.extensions = []
        self.threads = threads
        self.pool = None
        self.die = False
        self.results = []
        self.notFound = set()
        self.verbosity = verbosity

        self.start_time = None
        self.stop_time = None

        self.nfh = NotFoundHandler()
        self.pool = Pool(threads)
        self.s = Session()
        self.s.headers= {'User-Agent':choice(useragents),'Connection':'Keep-Alive'}
        self.s.mount('https://',HTTPAdapter(max_retries= self.FATAL,pool_connections= self.POOL_CON,pool_maxsize = self.POOL_MAX))
        self.s.mount('http://',HTTPAdapter(max_retries= self.FATAL,pool_connections= self.POOL_CON,pool_maxsize = self.POOL_MAX))

        self.error_log = set()

        if not host.endswith('/'):
            host = host+'/'
        try:
            self.host = urlparse(host)
        except Exception,ex:
            print_error("Failure setting host: {msg}".format(msg=ex))
        try:
            self.extensions = set(map(lambda x: '.{ext}'.format(ext=x),filter(None,extensions.split(','))) + ['/',''])
        except Exception,ex:
            print_error("Failure setting extensions: {msg}".format(msg=ex))
        try:
            if wordlist.endswith('.gz'):
                self.wordlist = set(map(lambda x: x.replace('\r',''),filter(None,gzip.open(wordlist,'rb').read().split('\n'))))
            else:
                self.wordlist = set(filter(None,open(wordlist).read().split('\n')))
        except Exception,ex:
            print_error("Failure loading wordlist {wordlist}:{msg}".format(wordlist=wordlist,msg=ex))

        self.queue = Queue( len(self.wordlist) * len(self.extensions) )
        if self.verbosity > 1:
            print_info("Building queue....")
        for word in self.wordlist:
            for ext in self.extensions:
                self.queue.put(word+ext)
        if self.verbosity > 1:
            print_success("Queue built.")
        self.total = self.queue.qsize()

    def __log_error(self,msg):
        etime = datetime.now().strftime("%H-%M-%S-%f")
        self.error_log.add("{etime}::{msg}".format(etime=etime,msg=msg))

    def __fetch(self):
        while not self.queue.empty():
            if self.die:
                return
            uri = self.queue.get()
            response = None
            try:
                url = urljoin(self.host.geturl(),uri)
                if self.verbosity > 1:
                    print_info("requesting {url}".format(url=url))
                response = self.s.get(url,allow_redirects=False,verify=False)
                code = response.status_code
                body = response.text
                if self.verbosity > 2:
                    print_info("response {url}: {code} {size}".format(url=url,code=code,size=len(body)))
                self.results.append(Probe(url,code,body))
                self.FAILS = 0

            except Exception,ex:
                self.FAILS +=1
                self.queue.put(uri)
                msg = "Error [{url}] {etype}::{msg}".format(url=urljoin(self.host.geturl(),uri),etype=type(ex),msg=ex)
                print_error(msg)
                self.__log_error(msg)

    def probe_missing_response(self,custom_urls=[]):
        if custom_urls:
            for url in custom_urls:
                try:
                    if self.verbosity > 1:
                        print_info("404 Probe: [{url}]".format(url=url))
                    r = self.s.get(url,allow_redirects=False,verify=False)
                    self.nfh.add(url,r.status_code,r.text)
                except Exception,ex:
                    msg = "Failed probe_missing {host}: {etype}::{msg}".format(host=self.host.geturl(),etype=type(ex),msg=ex)
                    print_error(msg)
                    self.__log_error(msg)
                    return False
        else:
            for _ in range(self.PROBE_MISSING_COUNT):
                for ext in self.extensions:
                    try:
                        uri = (random_nstring(20)+ext).strip()
                        url = urljoin(self.host.geturl(),uri)
                        if self.verbosity > 1:
                            print_info("404 Probe: [{url}]".format(url=url))
                        r = self.s.get(url,allow_redirects=False,verify=False)
                        self.nfh.add(url,r.status_code,r.text)
                    except Exception,ex:
                        msg = "Failed probe_missing {host}: {etype}::{msg}".format(host=self.host.geturl(),etype=type(ex),msg=ex)
                        print_error(msg)
                        self.__log_error(msg)
                        return False
        return True

    def __analyze_findings(self):
        if self.verbosity:
            print_success("Analyze thread spawned")
        while True:
            if self.die:
                return
            for probe in filter(lambda probe: hasattr(probe,"body"),self.results):
                if self.nfh.is_not_found(probe):
                    probe.code = 404
                del(probe.body)
            sleep(10)
        if self.verbosity:
            print_success("Analyze thread completed")

    def run(self):
        self.start_time = datetime.now().strftime("%H-%M-%S-%f")
        a_thread = spawn(self.__analyze_findings)
        if self.probe_missing_response():
            for _ in xrange(self.threads):
                self.pool.spawn(self.__fetch)

            start_t = timeit.default_timer()
            start_q = self.queue.qsize()
            while not self.queue.empty():
                if self.FAILS >= self.MAX_FAIL:
                    self.die = True
                    break
                if self.verbosity:
                    current_t = timeit.default_timer()
                    t_delta = current_t - start_t
                    if t_delta >= self.INTERVAL_S:
                        current_q = self.queue.qsize()
                        q_delta = start_q - current_q
                        req_s = 0 if not q_delta else q_delta/self.INTERVAL_S
                        print_info("[{url}] {completed}/{total} {req_s} req/s".format(url=self.host.geturl(),total=self.total,completed=self.total-current_q,req_s=req_s))

                        start_t = current_t
                        start_q = current_q

                if len(self.pool.greenlets) < self.threads:
                    for _ in xrange(self.threads - len(self.pool.greenlets)):
                        self.pool.spawn(self.__fetch)
                sleep(5)

            self.pool.join()
            self.die = True
            a_thread.join()
        self.end_time = datetime.now().strftime("%H-%M-%S-%f")

if __name__== "__main__":
    parser = argparse.ArgumentParser(prog='FDB.py',description='single headless db. for testing and single targets')
    parser.add_argument("-e","--extensions",help="extentions to test. commma delimitted",required=True)
    parser.add_argument("-H","--host",help="protocol://host:port/",required=True)
    parser.add_argument("-o","--outputFile",help="Output file. cvs. code,path,size")
    parser.add_argument("-t","--threads",help="thread count",type=int,default=5)
    parser.add_argument("-l","--wordlist",help="wordlist to run",required=True)
    parser.add_argument("-v","--verbosity",help="verbose level; v,vv",action="count",default=0)

    if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(0)

    args = parser.parse_args()

    output_file = "{host}_{timestamp}.txt".format(host=re.sub('[/:]+','_',args.host),timestamp=datetime.now().strftime("%H-%M-%S-%f"))
    try:
        output = open(output_file,'w')
    except Exception,ex:
        print_error("Failed creating output file {filename}: {msg}".format(filename=output_file,msg=ex))
        sys.exit(2)


    output.write("#{host}\n".format(host=args.host))
    output.write("#start: {timestamp}\n".format(timestamp=datetime.now().strftime("%m-%d-%y_%H:%M:%S.%f")))
    output.write("#wordlist: {wordlist}\n".format(wordlist=args.wordlist))
    output.write("#extensions: {exts}\n".format(exts=args.extensions))
    output.flush()
    myfdb = FDB(args.host,args.wordlist,args.extensions,args.threads,args.verbosity)
    try:
        myfdb.run()
    except KeyboardInterrupt:
        myfdb.die = True

    for x in filter(lambda x: x.code != 404,myfdb.results):
        output.write("{code},{url},{length}\n".format(url=x.url,code=x.code,length=x.length))
    for e in myfdb.error_log:
        output.write("# {msg}\n".format(msg=e))
    output.write("#stop: {timestamp}\n".format(timestamp=datetime.now().strftime("%m-%d-%y_%H:%M:%S.%f")))
    output.close()
