#!/usr/bin/env python3

from packaging import version
import sys

a = str(sys.argv[1])
b = str(sys.argv[2])

print('Checking if %s is equal or newer than %s...' % (a, b))
result = version.parse(a) >= version.parse(b)
if result:
    print('OK: %s is equal or newer than %s' % (a, b))
else:
    print('ERROR: %s is older than %s' % (a, b))
sys.exit(not result)
