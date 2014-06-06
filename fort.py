__author__ = 'adz'
#!/usr/bin/python

import sys

def parsetheconfig(conf):
    startofrules = "config firewall policy"
    startofrule = "edit"
    endofrule = "next"
    endofrules = "end"
    rulelist = []
    temporaryrulelist = []
    parsingrule = False
    parsingrules = False
    with open(conf, 'r') as f:
        data = f.readlines()

        for line in data:
            if "Hostname" in line:
                hostname = line.split()[1]

            if startofrules in line:
                #If were here, we have started the firewall rules
                parsingrules = True
            if endofrules in line:
                #if were here, we have ended the firewall rules
                parsingrules = False

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

            if parsingrules + parsingrule == 2:
                #if here, we have started parsing rules and a rule
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

    for rule in rulelist:
        for key, value in baddict.iteritems():
            if value in rule:
                print "Alert Rule found with " + key + " rule -> " + rule[0]
                alerts[key].append(rule[0].replace("edit", "rule"))

    for key, value in alerts.iteritems():
        print key, value
        print key, len(value)


if __name__ == "__main__":
    main()