import sys,string
from datetime import datetime
from random import choice

class color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELO = '\033[93m'
    RED = '\033[91m'
    OPTIMUM = '\033[7m'
    NOPTIMUM = '\033[2m'
    ENDC = '\033[0m'

def print_error(msg):
    sys.stderr.write("%s[!]%s %s: %s\n" % (color.RED,color.ENDC,datetime.now().strftime("%H:%M:%S.%f"),msg))

def print_warning(msg):
    sys.stderr.write("%s[W]%s %s: %s\n" % (color.YELO,color.ENDC,datetime.now().strftime("%H:%M:%S.%f"),msg))

def print_info(msg):
    print "%s[I]%s %s: %s" % (color.BLUE,color.ENDC,datetime.now().strftime("%H:%M:%S.%f"),msg)

def print_success(msg):
    print "%s[*]%s %s: %s" % (color.GREEN,color.ENDC,datetime.now().strftime("%H:%M:%S.%f"),msg)

def print_highlight(msg):
    print "%s[*]%s %s: %s%s%s" % (color.GREEN,color.ENDC,datetime.now().strftime("%H:%M:%S.%f"),color.OPTIMUM,msg,color.ENDC)

def random_nstring(n):
    return ''.join(choice(string.ascii_letters) for _ in range(n))

useragents = [ \
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)", \
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36", \
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",\
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0",\
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",\
        "Mozilla/5.0 (iPad; CPU OS 6_1_3 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B329 Safari/8536.25"]
