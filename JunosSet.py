__author__ = 'adz'
#!/usr/bin/python

import sys
from netaddr import *
import re
import os
import commonfunctions


debug = "no"




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
                    logicalsystem = "BaseSystem"

                #if permitedpolicy.split[5] == "global":
                    #Global policies are shorter.

                questionablebit = policyfoundinconfig.split('policy')[1]

                if debug == "yes":
                    print "[*] Alert Rule found with " + key + " rule -> " + questionablebit
                    print "Line was:"
                    print policyfoundinconfig
                    print questionablebit.split("match")[0].strip(" ")

                entry = questionablebit.split("match")[0].strip(" ")
                entry = entry.split("then")[0]

                entry = logicalsystem + " " + entry

                entrydictionary = {entry: policyfoundinconfig}
                alerts[key].append(entrydictionary)


    #Now we have our questionable rules, Lets see if they are permited rather than denies
    report = []
    print str(alerts["hostname"]).upper()
    print "---Summary---"

    report.append("[I] Total policy line entries : " + str(len(policiesfoundinconfig)) + "\n")
    report.append("[I] Total Categories of issues Searched for " + str(baddictinit) + "\n")
    report.append("[I] Additional Categories found during parsing " + str(len(baddict) - baddictinit) + "\n")
    report.append("[I] Additions were " + str(badadditions) + "\n")

    hostname = alerts["hostname"].upper()
    basedir = "outputs/" + hostname
    commonfunctions.makedirs(basedir)

    for key, value in alerts.iteritems():
        if key != "hostname":
            dir = basedir + "/" + key.replace("/", "_")
            commonfunctions.makedirs(dir)
            type = key
            for entrydictionary in value:
                for key, value in entrydictionary.iteritems():
                    virtualsystem = key.split()[0]

                    finaldir = dir + "/" + virtualsystem
                    commonfunctions.makedirs(dir + "/" + virtualsystem)

                    if any(key.split()[1] in permitted for permitted in permittedpolicies):

                        #print "[!] " + key + " policy entry " + value

                        with open(finaldir + "/" + key.split()[1], 'a') as f:
                                f.write(value)

                        report.append("[!] " + type + " " + key + " policy entry below \n" + value + "\n")


    with open(basedir + "/summary.txt", 'a') as f:
        for each in commonfunctions.f2(report):
            f.write(each)



def main():
    parsetheconfig(sys.argv[1])

if __name__ == "__main__":
    main()