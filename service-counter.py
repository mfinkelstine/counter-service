#!/usr/bin/env python

import os.path

class NginxLogAnalyzer():

    def __init__(self, readfile, writefile, topcount=5):

        self.summary = {
            "requests": {},
            "ips": {},
            "useragents": {}
        }

        self.topcount = topcount

        self.reafile = readfile
        self.writefile = writefile

    def log_analyze(self):

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
        self.write_summary()

    def summarize(self, cols):
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

    def write_summary(self):
        summary = open(self.writefile, 'w')
        summary.write("Log summary\n")
        for key in self.summary:
            list = sorted(self.summary[key].items(), key=lambda x: x[1], reverse=True)
            list = list[:self.topcount]
            summary.write("\nTop "+key+":\n")
            for l in list:
                summary.write(l[0]+": "+str(l[1])+" times\n")
        summary.close()

    @staticmethod
    def find_chars(string, char):

        return [i for i, ltr in enumerate(string) if ltr == char]


if __name__ == '__main__':
    logfile = '/var/log/nginx/access.log'
    summaryfile = './access_summary.log'
    summary = NginxLogAnalyzer(logfile, summaryfile, 5)
    summary.log_analyze()