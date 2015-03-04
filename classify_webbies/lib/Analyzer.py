from difflib import SequenceMatcher
from Common import *
import os,sys

class Analyzer:
    def __init__(self,threshold = 0.85):
        self.threshold = threshold

    def analyze(self,webbies):
        lookupTable= {}
        groups = {}
        groupNo = 0
        print_info("Generating Lookup Table")
        s = SequenceMatcher(isjunk=lambda x: x in " \t",autojunk=False)
        for webby in webbies:
            s.set_seq2(webby.lastResponse)
            for xwebby in webbies:
                if webby != xwebby:
                    if webby not in lookupTable:
                        lookupTable[webby] = {}
                    if xwebby not in lookupTable[webby]:
                        s.set_seq1(xwebby.lastResponse)
                        match = s.quick_ratio()
                        lookupTable[webby][xwebby] = match
                        if xwebby not in lookupTable:
                            lookupTable[xwebby] = {}
                        lookupTable[xwebby][webby] = match

        print_info("Creating Groups")
        for webby in webbies:
            if webby.code and webby.success and not webby.group:
                match = False
                for groupNo,webbies in groups.items():
                    matched = 0
                    for xwebby in webbies:
                        if lookupTable[webby][xwebby] > self.threshold and xwebby.code == webby.code:
                            matched+=1
                    if matched == len(webbies):
                        webby.group = groupNo
                        webbies.append(webby)
                        match = True
                        break
                if not match:
                    groupNo+=1
                    groups[groupNo] = [webby]
                    webby.group = groupNo
                    for xwebby in webbies:
                        if xwebby.code == webby.code and xwebby != webby:
                            if lookupTable[webby][xwebby] > self.threshold:
                                xwebby.group = webby.group
                                groups[groupNo].append(xwebby)
