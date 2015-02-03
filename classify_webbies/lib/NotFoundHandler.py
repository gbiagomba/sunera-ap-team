from Probe import *
from difflib import SequenceMatcher

class NotFoundHandler:
    def __init__(self,threshold=0.9):
        self.threshold= threshold
        self.history = []
        self.avgl = 0
    def update_thresholde(self,threshold):
        self.threshold = threshold

    def add(self,url,code,body):
        self.history.append(Probe(url,code,body))
        l = 0
        for b in [x.body for x in self.history]:
           l += len(b)

        self.avgl = l/len(self.history)
        if self.avgl < 50:
            self.threshold = 1.0

    def is_not_found(self,xprobe):
        if xprobe.code in [n.code for n in self.history]:
            s = SequenceMatcher(isjunk=lambda x: x in " \t",autojunk=False)
            s.set_seq2(xprobe.body)
            for body in [ n.body for n in filter(lambda y: y.code ==xprobe.code,self.history)]:
                s.set_seq1(body)
                if s.quick_ratio() > self.threshold:
                    return True
        return False
