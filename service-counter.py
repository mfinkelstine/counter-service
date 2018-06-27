#!/usr/bin/env python

import argparse
import os
import time

class NginxLogAnalyzer():

    def __init__(self, readfile, writefile, topcount=5):
        """

        :param readfile: str
        :param writefile: str
        :param topcount: int
        """

        self.summary = {
            "requests": {},
            "ips": {},
            "useragents": {}
        }

        self.topcount = topcount
        self.reafile = readfile
        self.writefile = writefile

    def log_analyze(self):
        """

        :return:
        """

        if not os.path.isfile(self.reafile):
            print(self.reafile, "does not exist! exiting")
            exit(1)

        log = open(self.reafile, 'r')
        lines = log.readlines()
        log.close()
        loglist = []

        for s in lines:
            line = s.strip()
            tmp = line.split(' ')
            ip = tmp[0]

            doublequotes = NginxLogAnalyzer.find_chars(line, '"')
            request_start = doublequotes[0]+1
            request_end = doublequotes[1]
            useragent_start = doublequotes[4]+1
            useragent_end = doublequotes[5]

            request = line[request_start:request_end]
            useragent = line[useragent_start:useragent_end]

            loglist.append({
                "ip": ip,
                "request": request,
                "useragent": useragent
            })

        self.summarize(loglist)
        self.create_text_summery()

    def summarize(self, cols):
        """
        :param cols:
        :return:
        """
        for col in cols:
            if not col['request'] in self.summary['requests']:
                self.summary['requests'][col['request']] = 0
            self.summary['requests'][col['request']] += 1

            if not col['ip'] in self.summary['ips']:
                self.summary['ips'][col['ip']] = 0
            self.summary['ips'][col['ip']] += 1

            if not col['useragent'] in self.summary['useragents']:
                self.summary['useragents'][col['useragent']] = 0
            self.summary['useragents'][col['useragent']] += 1

    def create_text_summery(self):
        """
        :return:
        """
        summary = open(self.writefile, 'w')
        summary.write("Log summary\n")
        for key in self.summary:
            list = sorted(self.summary[key].items(), key=lambda x: x[1], reverse=True)
            list = list[:self.topcount]
            summary.write("\nTop "+key+":\n")
            for l in list:
                summary.write(l[0]+": "+str(l[1])+" times\n")
        summary.close()

    def create_html_summery(self):

        summary = open(self.writefile, 'w')
        summary.write("Log summary\n")
        for key in self.summary:
            list = sorted(self.summary[key].items(), key=lambda x: x[1], reverse=True)
            list = list[:self.topcount]
            summary.write("\nTop " + key + ":\n")
            for l in list:
                summary.write(l[0] + ": " + str(l[1]) + " times\n")
        summary.close()

    def create_html_summery(self):

        html_context = "<!DOCTYPE html>\n<html>\n<head>\n<link rel=\"stylesheet\" href=\"css/table.css\">\n\
        <title>CP Test</title>\n</head>\n\
        <body>\n<h1>CP TEST</h1>\n"

        html_close = "\n</body>\n\t</html>\n"
        table_header = "\n\t<tr>\n\t\t<th colspand=\"2\">Top %s</th>\n\t</tr>\n"
        table_data = "\n\t<tr>\n\t\t<td>%s</td>\n\t\t<td>%s</td>\n\t</tr>"

        html_page = open(self.writefile, 'w')
        html_page.write(html_context)
        table_start = "\n<table>"
        table_end = "\n</table>\n<br>\n<br>\n<br>"
        for key in self.summary:
            html_page.write(table_start)
            list = sorted(self.summary[key].items(), key=lambda x: x[1], reverse=True)
            list = list[:self.topcount]
            html_page.write(table_header % (key))
            for l in list:
                html_page.write(table_data % (str(l[1]), l[0]))

            html_page.write(table_end)
        html_page.write(html_close)
        html_page.close()

    @staticmethod
    def find_chars(string, char):

        return [i for i, ltr in enumerate(string) if ltr == char]

def check_args():
    """

    :return: str
    """
    parser = argparse.ArgumentParser(description="POST & GET Counter ")
    parser.add_argument("--logfile", dest='logfile', type=str, default="access.log", help="Log file to parse")
    parser.add_argument("--path",    dest='path',    type=str, default="/var/log/nginx", help="Log Location")
    parser.add_argument("--opfile",  dest='opf',     type=str, default="index.html", help="Output file name")
    parser.add_argument("--opfl",    dest='opfl',    type=str, default="/nginx_counters/web/counter", help="Output file Save Location")
    parser.add_argument("--ext",     dest='ext',     type=str, default="html", help="Extention Type , supported : html,cvs")
    parser.add_argument("--ctop",    dest='ctop',     type=int, default="5", help="top recoards")

    return parser.parse_args()

if __name__ == '__main__':

    args = check_args()
    logfile = args.path + "/" + args.logfile
    summaryfile = args.opfl + "/" + args.opf

    while True:

        time.sleep(5)
        summary = NginxLogAnalyzer(logfile, summaryfile, args.top)
        summary.log_analyze()
        if args.ext == "html":
            summary.create_html_summery()
        elif args.ext == "txt":
            summary.create_text_summery()
