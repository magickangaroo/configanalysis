__author__ = 'adz'
#!/usr/bin/python

import sys

def parsetheconfig(conf):

    baddict = {
        'opendest': 'destination-address any',
        'opensource':'source-address any',
        'openservice': 'application any'
    }

    alerts = {'hostname': "unknown"}

    for key, value in baddict.iteritems():
        alerts[key] = []

    with open(conf, 'r') as f:
        data = f.readlines()

        for line in data:
            if "host-name" in line:
                alerts["hostname"] = line.split()[-1]

            if "security policies" in line:

                for key, value in baddict.iteritems():
                    if value in line:
                        questionablebit = line.split('policy')[1]
                        print "Alert Rule found with " + key + " rule -> " + questionablebit

                        alerts[key].append(questionablebit.split("match")[0].strip(" "))

    for key, value in alerts.iteritems():
        print key, value, len(value)

        print "\n"


def main():
    parsetheconfig(sys.argv[1])




if __name__ == "__main__":
    main()