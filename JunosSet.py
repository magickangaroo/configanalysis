__author__ = 'adz'
#!/usr/bin/python

import sys
from netaddr import *
import re

debug = "yes"

def f2(seq):
   # order preserving
   checked = []
   for e in seq:
       if e not in checked:
           checked.append(e)
   return checked




def parsetheconfig(conf):

    baddict = {
        'opendest': 'destination-address any',
        'opensource':'source-address any',
        'openservice': 'application any',
    }

    baddictinit = len(baddict)
    badadditions = []

    alerts = {'hostname': "Unknown"}
    policiesfoundinconfig = []
    permittedpolicies = []
    addresses = []

    with open(conf, 'r') as f:
        data = f.readlines()

        for line in data:

            if "host-name" in line:
                if alerts["hostname"] == "Unknown":
                    alerts["hostname"] = line.split()[-1]

            if "security address-book" in line:
                if "address-set" not in line:
                    ip = line.split()[-1]
                    ipcheck = re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}($|/.*)$", ip)

                    if ipcheck:
                        if IPNetwork(ip).size >= 65536:
                    #/16
                            name = line.split()[-2]
                            entry = {name: ip}
                            baddict[ip] = name
                            badadditions.append(entry)

            if "security policies" in line:
                #if "permit" in line:
                policiesfoundinconfig.append(line)
                if "then permit" in line:
                    permittedpolicies.append(line)

    for key, value in baddict.iteritems():
            #if any(value in x for x in permitedpolicies):
        alerts[key] = []
        for policyfoundinconfig in policiesfoundinconfig:
            if value in policyfoundinconfig:
                if policyfoundinconfig.split()[1] == "logical-systems":
                    #were dealing with logical system
                    logicalsystem = policyfoundinconfig.split()[2]
                else:
                    logicalsystem = "Base"

                #if permitedpolicy.split[5] == "global":
                    #Global policies are shorter.

                questionablebit = policyfoundinconfig.split('policy')[1]

                if debug == "yes":
                    print "[*] Alert Rule found with " + key + " rule -> " + questionablebit
                    print "Line was:"
                    print questionablebit.split("match")[0].strip(" ")

                entry = questionablebit.split("match")[0].strip(" ")
                entry = entry.split("then")[0]
                if logicalsystem != "base":
                    entry = logicalsystem + " " + entry
                alerts[key].append(entry)


    #Now we have our questionable rules, Lets see if they are permited rather than denies
    print str(alerts["hostname"]).upper()
    print "---Summary---"

    print "[I] Total permited policies line entries : " + str(len(policiesfoundinconfig))
    print "[I] Total Catogories of issues Searched for " + str(baddictinit)
    print "[I] Additional Catagories found during parsing " + str(len(baddict) - baddictinit)
    print "[I] Additions were " + str(badadditions)
    report = []
    #print permitedpolicies
    for key, value in alerts.iteritems():
        if key != "hostname":
            for entry in value:
                if any(entry.split()[1] in permitted for permitted in permittedpolicies):
                    report.append("[!] " + key + " policy named " + entry)

    for each in f2(report):
        print each

def main():
    parsetheconfig(sys.argv[1])




if __name__ == "__main__":
    main()