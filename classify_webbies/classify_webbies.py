#!/usr/bin/env python2.7

#    Copyright (C) 2014 Sunera, LLC
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
#    Version:           4.4
#    Code Repo:         http://code.google.com/p/sunera-ap-team/

import sys,argparse,os
import cPickle as pickle
from random import choice
from lib.Classifier import Classifier
from lib.Webby import Webby
from lib.Common import *
from lib.Screenshots import Screenshots
from lib.Scope import Scope
from lib.Analyzer import Analyzer
from lib.Harvester import Harvester
from lib.DNSHandler import DNSHandler

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='classify.webbies.py',description='enumerate and display detailed information about web listeners')
    parser.add_argument("-A","--analyze",help="analyze web listeners responses and group according similarity",action='store_true')
    parser.add_argument("-b","--bing_key",help="bing API key",default="")
    parser.add_argument("-g","--gnmap",help="gnmap input file")
    parser.add_argument("-G","--gnmapdir",help="Directory containing gnmap input files")
    parser.add_argument("-i","--inputList",help="input file with hosts listed http(s)://ip:port/ or ip:port per line")
    parser.add_argument("-n","--nessus",help="nessus input file")
    parser.add_argument("-N","--nessusdir",help="Directory containing nessus files")
    parser.add_argument("-o","--output",help="Output file. Supported types are csv. default is lastrun.csv",default="lastrun.csv")
    parser.add_argument("-P","--pickle",help="pickle file to restore previous run",default="")
    parser.add_argument("-R","--resolvers",help="Specify custom nameservers to resolve IP/hostname. Comma delimited",default="")
    parser.add_argument("-s","--scope",help="Scope file with IP Networks in CIDR format",default="")
    parser.add_argument("-S","--screenshots",help="enables and specifies screenshot dir. REQUIRES PHANTOMJS",default=None)
    parser.add_argument("-T","--threads",type=int,help="Set the max number of threads.",default=5)
    parser.add_argument("-u","--useragents",help="specifies file of user-agents to randomly use.",default=None)
    parser.add_argument("-v","--verbosity",help="-v for regular output, -vv for debug level",action="count",default=0)
    parser.add_argument("-V","--version",action='version',version='%(prog)s 4.4')
    parser.add_argument("-X","--nolookups",help="disable additional reverse resolving",action='store_true')

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    webbies = set()

    if args.useragents:
        useragents = filter(None,open(args.useragents).read().split('\n'))

    restore = False
    myClassifier = None

    if os.path.isfile('.lastrun.p'):
        print_info(".lastrun.p detected.")
        if raw_input('Restore last run? [Y/n]: ').lower() != 'n':
            restore = True

    if not restore and not args.pickle:
        myHarvester = Harvester(args.verbosity)
        if args.nessus:
            myHarvester.harvestNessus(args.nessus)
        if args.nessusdir:
            myHarvester.harvestNessusDir(args.nessusdir)
        if args.gnmap:
            myHarvester.harvestGnmap(args.gnmap)
        if args.gnmapdir:
            myHarvester.harvestGnmapDir(args.gnmapdir)
        if args.inputList:
            myHarvester.harvestIL(args.inputList)

        webbies = myHarvester.webbies

        if args.scope:
            try:
                iprange = filter(None,open(args.scope).read().split('\n'))
                myScope = Scope(iprange)
                if not myScope.nets:
                    print_error("Scope not set. Aborting")
                    sys.exit(1)
                print_info("Scope set to networks listed in '%s'" % args.scope)
            except Exception,ex:
                print_error("Failed reading scope argument. %s" % ex)
                sys.exit(0)
        else:
            iprange = filter(None,map(lambda x: x.ip,webbies))
            myScope = Scope(iprange)

        myClassifier = Classifier(
                scopeObj=myScope,
                startingWebbies=webbies,
                useragents=useragents,
                threadCount = args.threads,
                verbosity = args.verbosity,
                nolookups = args.nolookups,
                resolvers = args.resolvers.split(','),
                bing_key = args.bing_key
                )

    else:
        restoref = args.pickle if args.pickle else ".lastrun.p"
        print_info("Restoring classifier from pickle file '%s'" % restoref)
        try:
            with open(restoref,'rb') as fp:
                myClassifier = pickle.load(fp)
                #update options
                if args.threads:
                    myClassifier.threadCount = args.threads
                if args.verbosity:
                    myClassifier.verbosity = args.verbosity
                if args.resolvers:
                    myClassifier.resolvers = args.resolvers.split(',')
                myClassifier.reinit()

        except Exception,ex:
            print_error("Failed opening pickle file. %s" % ex)
            sys.exit(1)

    try:
        myClassifier.run()
    except KeyboardInterrupt:
        print "Keyboard interupt detected. saving storage to .lastrun.p and exiting"
        with open('.lastrun.p','wb') as fp:
            del(myClassifier.webbyPool)
            del(myClassifier.DNSPool)
            pickle.dump(myClassifier,fp)
        sys.exit(0)

    with open('.lastrun.p','wb') as fp:
        del(myClassifier.webbyPool)
        del(myClassifier.DNSPool)
        pickle.dump(myClassifier,fp)

    if args.analyze:
        print_highlight("Analyzing webbies")
        myAnalyzer = Analyzer()
        myAnalyzer.analyze(myClassifier.storage)

    if args.output:
        try:
            with open(args.output,'w') as fp:
                fp.write("#ip,hostname,port,protocol,service,banner,notes,priority\n")
                for webby in myClassifier.storage:
                    fp.write("%s\n"% str(webby))
            with open(args.output+'.p','wb') as fp:
                pickle.dump(myClassifier,fp)
            print_highlight("successfully saved to '%s'" % (args.output))
        except Exception,ex:
            print_error("error saving output file. '%s'" % (ex))

    if args.screenshots:
        myScreenshots = Screenshots(args.screenshots,choice(useragents),args.threads)
        myScreenshots.gatherScreens(myClassifier.storage)
