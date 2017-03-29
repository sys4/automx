#!/usr/bin/python

import dns.resolver
import re
import sys

domain = str(sys.argv[1])

try:
    mx_objects = dns.resolver.query(domain,'MX')
except:
    print str(sys.argv[2])
    sys.exit(0)

mx_server = {}

for server in mx_objects:
    mx_server[server.preference] = server.exchange

primary_mx_server = re.sub('\.$', '', mx_server[sorted(mx_server)[0]].to_text())

print primary_mx_server

