#!/usr/bin/env python

#    Copyright (C) 2013 Sunera, LLC
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
#    Author:		Nick Popovich	
#    Blog:		http://security.sunera.com/
#
#    Program Name:	nessus_downer.py
#    Purpose:		Download Nessus reports via command line
#    Version:		1.0
#    Code Repo:		http://code.google.com/p/sunera-ap-team/

import sys, urllib, urllib2, getpass, cookielib, time, fnmatch, re, os
import xml.etree.ElementTree as ET
from optparse import OptionParser
from HTMLParser import HTMLParser

usage = 'python %prog [-t https://127.0.0.1:8834] [-r nessus|nbe|both]\n\nFollow prompts.  Report name search string can be any part of the reports name that you want to download (case insensitive). Leave it blank to display all reports on scanner.\nReport files will be downloaded to the current directory with .nessus\\nbe appended to the report name.  Be aware that it takes a while to generate large nbe reports--the script will wait for Nessus to generate a .nbe and then download when complete.'

parser = OptionParser(usage=usage)
parser.add_option("-t", "--target", action="store", dest="nessus_server", default="https://127.0.0.1:8834",
	 help="set the target URL protocol, host and port. Defaults to https://127.0.0.1:8834")
parser.add_option("-r", "--report", action="store", dest="report", default="both", 
         help="choose the type of report output.  Available types are 'nessus', 'nbe' or 'both' (default) to save both types.  Omit quotes when passing as an argument.")
parser.add_option("-f", "--force", action="store_true", dest="force", default=False,
 help="Force overwriting report files that already exist (same name) in the current directory.  Passing the -f switch will overwrite existing files, while omiting will skip the file that exists and download only new reports (default behavior).")
(options, args) = parser.parse_args()

if options.report not in ['nessus', 'nbe', 'both']:
     print "Error: invalid report type requested\n"
     parser.print_help()
     sys.exit(1)

# HTML parser class to pull data from the status and content tags of respones when generating an nbe file
class MyHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.content = None
	self.status = None
	self.flag = 0
    def handle_starttag(self, tag, attrs):
        if tag == 'meta':
            for key, value in attrs:
                if key == 'content':
		    self.content = value[6:]
		    self.status = value[:1]
    
def get_content_meta(url):
    html_parser = MyHTMLParser()
    html_parser.feed(url.read())
    html_parser.close()
    return html_parser.content

def get_status(url):
    html_parser = MyHTMLParser()
    html_parser.feed(url.read())
    html_parser.close()
    return html_parser.status

# XML parsing to get the report name and match on search string
def parse_report_list(xml_root, srch_str):
    root = ET.fromstring(xml_root)
    xml_elems = []
    for report in root.findall(".//report"):
        xml_out=report.find('name').text + ',' + report.find('readableName').text + "," + report.find('status').text
        xml_split=xml_out.split(',')
        if xml_split[2] == "completed":
            if fnmatch.fnmatch(xml_split[1].lower(), srch_str.lower()):
                xml_elems.append((xml_split[0],xml_split[1]))
    return xml_elems

# This is the function to download the .nessus file
def nessus_downloader(rprt_num,rprt_name):
    rprt_name = re.sub('[^\w]', '_', rprt_name)
    if not os.path.exists(rprt_name + ".nessus") or options.force == True:
        print '\nProcessing Nessus Scan: ' + xml_list[x][1] + '.nessus. Please wait...'
        report_dl = opener.open(options.nessus_server + '/file/report/download?report=' + rprt_num)
        f = open(rprt_name + '.nessus', 'w')
        f.write(report_dl.read())
        f.close()
        print '\n*** Nessus Scan: ' + xml_list[x][1] + '.nessus processing complete ***'
    else:
        print '\nNot set to force overwrite (no -f detected), skipping ' + rprt_name + '.nessus'

# This is the function to download the .nbe file
def nbe_downloader(rprt_num,rprt_name):
    rprt_name = re.sub('[^\w]', '_', rprt_name)
    if not os.path.exists(rprt_name + ".nbe") or options.force == True:
        print '\nProcessing Nessus Scan: ' + xml_list[x][1] + ".nbe. nbe's can take a long time if they're big, please wait..."
        nbe_opener = opener.open(options.nessus_server + '/file/xslt/?report=' + rprt_num + '&xslt=nbe.xsl')
        nbe_step1_url = get_content_meta(nbe_opener)
        nbe_step1_opener = opener.open(options.nessus_server + nbe_step1_url)
        time.sleep(1)
        while True:
            nbe_step1b_opener = opener.open(options.nessus_server + nbe_step1_url)
            nbe_step1b_status = get_status(nbe_step1b_opener)
            time.sleep(3)
            if nbe_step1b_status == '0':
                break
        nbe_step2_opener = opener.open(options.nessus_server + nbe_step1_url + '&step=2')
        f = open(rprt_name + '.nbe', 'w')
        f.write(nbe_step2_opener.read())
        f.close()
        print '\n*** Nessus Scan: ' + xml_list[x][1] + '.nbe processing complete ***'
    else:
        print '\nNot set to force overwrite (no -f detected), skipping ' + rprt_name + '.nbe'

def list_reports(srch_str):
    xml_list = []
    report_list = opener.open(options.nessus_server + '/report/list')
    report_list_xml = report_list.read()

    xml_list.extend(parse_report_list(report_list_xml, srch_str))
    for x in range(len(xml_list)):
        print 'Nessus Scan: ' + xml_list[x][1]
    return xml_list

def login(username, pdub):
    # Issue HTTP requests to log in to Nessus and pull reports
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
    login_data = urllib.urlencode({'login' : username, 'password' : pdub})
    login_opener = opener.open(options.nessus_server + '/login', login_data)
    del pdub
    root = ET.fromstring(login_opener.read())
    status = root.find('./status').text

    return status

# Remove trailing / if they supplied one
if options.nessus_server[len(options.nessus_server)-1] == "/":
    options.nessus_server = options.nessus_server[:-1]

# Setup cookie handling and test connectivity before we ask for user/pass
cj = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
try:
    opener.open(options.nessus_server + '/')
except urllib2.URLError as e:
    print "Connection to target server " + options.nessus_server + " failed: " + str(e.reason)
    print "\nCheck if target was specified correctly or is not running."
    sys.exit(1)

print "Connected to Nessus server " + options.nessus_server

status = ""
while status != "OK":
    username=raw_input('Enter Nessus Username: ')
    pdub = getpass.getpass()
    status = login(username, pdub)
    del pdub

    if status != "OK":
        print "Woops.. login failed! Please try again\n"

srch_str = '*' + raw_input('\nEnter report name search string. You can use Unix-like wildcards (e.g. * and ?) in the search string.\nLeave blank to display all available reports: ') + '*'
print '\n'
xml_list = list_reports(srch_str)

while srch_str != "":
    srch_str = raw_input('\nThe above report(s) matched your search criteria.\n\nPress Enter to download these reports or enter a new search string (CTRL+C to abort entirely): ')
    print '\n'
    if srch_str != "":
        xml_list = list_reports("*" + srch_str + "*")

for x in range(len(xml_list)):
    if options.report == 'both':
        nbe_downloader(xml_list[x][0],xml_list[x][1])
	nessus_downloader(xml_list[x][0],xml_list[x][1])
    elif options.report == 'nbe':
	nbe_downloader(xml_list[x][0],xml_list[x][1])
    elif options.report == 'nessus':
	nessus_downloader(xml_list[x][0],xml_list[x][1])

print '\nNessus file downloads 100% complete'
