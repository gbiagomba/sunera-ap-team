#!/usr/bin/env python2.7
#    Copyright (C) 2015 Sunera, LLC
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
#    Program Name:      fdb.py
#    Purpose:           dirbust mass amounts of web services
#    Version:           1.0
#    Code Repo:         http://code.google.com/p/sunera-ap-team/

from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool

from datetime import datetime
from urlparse import urlparse,urljoin
from Queue import Queue
from lib.Common import *
from lib.FDB import *

import sys,argparse,os
import cPickle as pickle

def run_fdb(q,wordlist,extensions,threads,verbosity,output_dir):
    host = q.get()
    print_info("Starting host {host}".format(host=host))
    output_file = "{host}_{timestamp}.txt".format(host=re.sub('[/:]+','_',host),timestamp=datetime.now().strftime("%H-%M-%S-%f"))
    output_file = os.path.join(output_dir,output_file)
    try:
        output = open(output_file,'w')
    except Exception,ex:
        print_error("Failed creating output file {filename}: {msg}".format(filename=output_file,msg=ex))
        return
    output.write("#{host}\n".format(host=host))
    output.write("#start: {timestamp}\n".format(timestamp=datetime.now().strftime("%m-%d-%y_%H:%M:%S.%f")))
    output.write("#wordlist: {wordlist}\n".format(wordlist=wordlist))
    output.write("#extensions: {exts}\n".format(exts=extensions))
    output.flush()
    myfdb = FDB(host,wordlist,extensions,threads,verbosity)
    try:
        myfdb.run()
    except (KeyboardInterrupt,SystemExit):
        myfdb.die = True
        q.put(host)

    for x in filter(lambda x: x.code != 404,myfdb.results):
        output.write("{code},{url},{length}\n".format(url=x.url,code=x.code,length=x.length))
    for entry in myfdb.error_log:
        output.write("# {msg}\n".format(msg=entry))
    output.write("#stop: {timestamp}\n".format(timestamp=datetime.now().strftime("%m-%d-%y_%H:%M:%S.%f")))
    output.close()

if __name__ == "__main__":
    STATE_FILE = '.fdb_lastrun.p'
    parser = argparse.ArgumentParser(prog='fdb.py',description='replacement for headless mode for mass dirbust')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-iL','--input_list',help="list of hosts to dirbust. <scheme>://<host>:<port> format")
    group.add_argument('-p','--pickle_file',help="load urls from webbies pickle file")
    group.add_argument('-r','--restore_state',help="continue from previous fdb session")

    parser.add_argument('-b','--base_dir',help="base directory",default="")
    parser.add_argument("-e","--extensions",help="extentions to test. commma delimitted",required=True)
    parser.add_argument("-fT","--fdb_threads",help="thread count for each host",type=int,default=10)
    parser.add_argument("-T","--threads",help="number of fdb's to run",type=int,default=5)
    parser.add_argument("-l","--wordlist",help="wordlist to run",required=True)
    parser.add_argument("-o","--output_directory",help="directory to save output files",default="./fdb_run/")
    parser.add_argument("-v","--verbosity",help="verbose level; v,vv,vvv",action="count",default=0)

    if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(0)

    args = parser.parse_args()

    try:
        if not os.path.exists(args.output_directory):
            os.makedirs(args.output_directory)
    except Exception,ex:
        print_error("Failed to create output directory: {msg}".format(msg=ex))
        sys.exit(1)

    restore = False
    q = Queue()
    if args.restore_state:
        STATE_FILE = args.restore
    if os.path.isfile(STATE_FILE):
        print_info("{sfile} detected.".format(sfile=STATE_FILE))
        if raw_input('Restore last run? [Y/n]: ').lower() != 'n':
            with open(STATE_FILE,'rb') as fp:
                r = pickle.load(fp)
                for i,h in enumerate(r,start=1):
                    print_info("[{i}] Restoring: {host}".format(i=i,host=h))
                print_success("Restored {x} hosts.".format(x=len(r)))
                if raw_input("Continue? [y/N]: ").lower() != 'y':
                    print_error("aborting...")
                    sys.exit(1)
                map(lambda x: q.put(x),r)
                restore = True

    if not restore:
        if args.base_dir:
            args.base_dir = "{base_dir}/".format(base_dir=args.base_dir.strip('/'))
        if args.input_list:
            try:
                for url in filter(None,open(args.input_list).read().split('\n')):
                    if args.base_dir:
                        url = urljoin(url,args.base_dir)
                    q.put(url)
            except Exception,ex:
                print_error("Failed to open {wordlist} or create queue: {msg}".format(wordlist=args.input_list,msg=ex))
                sys.exit(2)
        elif args.pickle_file:
            try:
                with open(args.pickle_file,'rb') as fp:
                    classifier = pickle.load(fp)
                    for webby in filter(lambda webby: webby.url and webby.success,classifier.storage):
                        x = urlparse(webby.url)
                        url = "{scheme}://{host}/".format(scheme=x.scheme,host=x.netloc)
                        if args.base_dir:
                            url+=base_dir
                        q.put(url)
            except Exception,ex:
                print_error("Failed to load urls from webbies file {wfile}: {msg}".format(wfile=args.pickle_file,msg=ex))
                sys.exit(3)

    pool = Pool(args.threads)
    total = q.qsize()
    if total:
        try:
            for _ in range(args.threads):
                pool.spawn(run_fdb,q,args.wordlist,args.extensions,args.fdb_threads,args.verbosity,args.output_directory)
            while not q.empty():
                if len(pool.greenlets) < args.threads:
                    for _ in xrange(args.threads - len(pool.greenlets)):
                        pool.spawn(run_fdb,q,args.wordlist,args.extensions,args.fdb_threads,args.verbosity,args.output_directory)
                print_info('{remain}/{total} hosts remain.'.format(remain=q.qsize(),total=total))
                sleep(60)
            pool.join()
        except KeyboardInterrupt:
            print_info("Crtl+C detected. Saving state to {sfile}.".format(sfile=STATE_FILE))
            sleep(2) #give time for threads to put current running host back into queue
            with open(STATE_FILE,'wb') as fp:
                save = set() #can't pickle Queue
                while not q.empty():
                    save.add(q.get())
                pickle.dump(save,fp)
    else:
        print_error("Queue is empty. Exiting")
        sys.exit(4)
