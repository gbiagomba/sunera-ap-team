import os,subprocess,shlex,re
from eventlet import GreenPool,Timeout
from Common import *

class Screenshots:
    def __init__(self,directory,useragent,threads):
        self.directory = directory
        self.useragent = useragent
        self.pool = GreenPool(size=threads)
        self.MAXTIME= 10

        if not os.path.exists(directory):
            os.makedirs(directory)

    def grabScreen(self,url):
        with Timeout(self.MAXTIME,False):
            filename = re.sub('[\W]+','.',url)
            if filename.endswith('.'):
                filename+="png"
            else:
                filename+=".png"

            command = "nice phantomjs --ignore-ssl-errors=yes %s/screenshot.js \"%s\" %s %s" % \
                (os.path.dirname(os.path.realpath(__file__)),self.useragent,url,self.directory+'/'+filename)

            proc = subprocess.Popen(shlex.split(command))
            proc.wait()

    def gatherScreens(self,webbies):
        for webby in webbies:
            if webby.code == 200 and webby.url:
                print_success("Grabbing screenshot of '%s'" % webby.url)
                self.pool.spawn_n(self.grabScreen,webby.url)
        self.pool.waitall()
