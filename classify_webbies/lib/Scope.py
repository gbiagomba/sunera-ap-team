from netaddr import IPNetwork,IPAddress
from Common import *

class Scope:
    def __init__(self,scope):
        self.nets = None

        try:
            self.nets = map(lambda x: IPNetwork(x),scope)
        except Exception,ex:
            print_error("Error setting scope object: '%s'" % ex)

    def inScope(self,host):
        for network in self.nets:
            if IPAddress(host) in network:
                return True
        return False
