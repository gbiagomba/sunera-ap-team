class Webby:
    def __init__(self,ip,hostname,port,firstrun=True):
        self.firstrun = firstrun
        self.ip = ip
        self.hostname = hostname
        self.port = port
        self.title = ""
        self.lastResponse = ""
        self.redirect = ""
        self.banner = ""
        self.code = 0
        self.forms = False
        self.login = False
        self.ssl = None
        self.success = True
        self.errormsg= ""
        self.url = ""
        self.group = 0

    #ip,hostname,port,protocol,service,banner,notes,priority
    def __str__(self):
        service = "https" if self.ssl else "http"
        login = "login" if self.login else ""
        forms = "forms" if self.forms else ""
        title = '"%s"' % self.title if self.title else ""
        if self.success:
            notes = " ".join([str(self.code),self.redirect if self.redirect else self.url,title,forms,login]).rstrip(' ')
        else:
            notes = """Error: {webby.errormsg}""".format(webby=self)
        csv = """{webby.ip},{webby.hostname},{webby.port},tcp,{service},{webby.banner},{notes},{webby.group}""".format(webby=self,service=service,notes=notes)
        return csv

    def __hash__(self):
        return hash(self.ip+self.hostname+self.port)

    def __eq__(self,other):
        return (self.ip,self.hostname,self.port) == (other.ip,other.hostname,other.port)
