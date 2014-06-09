__author__ = 'adz'
#!/usr/bin/python
from socket import inet_ntoa
from struct import pack
import sys
from string import *
import commonfunctions

def dotdectocidr(mask):

    (octet1, octet2, octet3, octet4) = mask.split(".")

    octet1 = int(octet1)
    octet2 = int(octet2)
    octet3 = int(octet3)
    octet4 = int(octet4)

    worker = octet1
    count = 0
    while worker != 0:
        if worker % 2 == 1:
            count = count + 1
        worker = worker/2

    worker = octet2
    while worker != 0:
        if worker % 2 == 1:
            count = count +1
        worker = worker/2

    worker = octet3
    while worker != 0:
        if worker % 2 == 1:
            count = count +1
        worker = worker/2

    worker = octet4
    while worker != 0:
        if worker % 2 == 1:
            count= count+1
        worker = worker/2

    return count

def parsetheconfig(conf):
    startofrules = "config firewall policy"
    startofrule = "edit"
    endofrule = "next"
    endofelement = "end"
    startofaddresss = "config firewall address"

    rulelist = []
    temporaryrulelist = []
    parsingrule = False
    parsingrules = False
    parsingaddresses = False
    previous = None
    next = None

    with open(conf, 'r') as f:
        rawdata = f.readlines()
        data = enumerate(rawdata)

        for index, line in data:
            #previous = line[index - 1]
            #next = line[index + 1]

            if "Hostname" in line:
                hostname = line.split()[1]

            if startofrules in line:
                #If were here, we have started the firewall rules
                parsingrules = True

            if startofaddresss in line:
                parsingaddresses = True

            if endofelement in line and "end-ip" not in line:

                if parsingrules == True:
                    #if were here, we have ended the firewall rules
                    parsingrules = False

                elif parsingaddresses == True:
                    parsingaddresses = False

            if startofrule in line:
                #if here we are starting a rule
                parsingrule = True

            if endofrule in line and parsingrule is True:
                #if here we are ending a rule
                if len(temporaryrulelist) > 0:
                    rulelist.append(temporaryrulelist)
                temporaryrulelist = []

            if endofrule in line:
                parsingrule = False

            if parsingaddresses == True:
                if "edit" in line:
                    #print line.split()[1]
                    nextline =  rawdata[index + 1]
                    if "subnet" in nextline:
                        subnet = nextline.split()[-1]
                        if dotdectocidr(subnet) <= 16:
                            print "alert subnet"

            if parsingrules + parsingrule == 2:
                #if here, we have started parsing rules and a rule
                #print line
                temporaryrulelist.append(line.strip('\r\n').strip(' '))


    return hostname, rulelist

def main():
    hostname, rulelist = parsetheconfig(sys.argv[1])

    baddict = {
        'opendest': 'set dstaddr "all"',
        'opensource':'set srcaddr "all"',
        'openservice': 'set service "ANY"'
    }

    alerts = {'hostname': hostname}

    for key, value in baddict.iteritems():
        alerts[key] = []
    hostname = alerts["hostname"].upper()
    basedir = "outputs/" + alerts["hostname"].upper()
    commonfunctions.makedirs(basedir)
    for rule in rulelist:
        for key, value in baddict.iteritems():
            if value in rule:
                entrydictionary = {rule[0].replace("edit", "rule"): rule}
                alerts[key].append(entrydictionary)


    report = []
    #report.append("[I] Total policy line entries : " + str(len(policiesfoundinconfig)) + "\n")
    report.append("\nAlerts for Firewall : " + hostname + "\n")

    for key, value in alerts.iteritems():


        if key != "hostname":
            report.append("\n[*] " + str(key) + " total " + str(len(value)) + "\n")
            entrydir = basedir + "/" + key
            commonfunctions.makedirs(entrydir)

            for entry in value:

                for name, rule in entry.iteritems():

                    report.append("[*] Found type " + key + " under " + name + "\n")
                    with open(entrydir + "/" + name, 'a') as f:
                        for eachline in rule:
                            f.write(eachline + "\n")


    with open(basedir + "/summary.txt", 'a') as f:
        for each in commonfunctions.f2(report):
            f.write(each)

if __name__ == "__main__":
    main()