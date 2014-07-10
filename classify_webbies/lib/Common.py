import sys
from datetime import datetime

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
