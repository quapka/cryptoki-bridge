#!/usr/bin/env python

import os

GROUP_ID = os.environ.get('GROUP_ID')
der = bytes.fromhex(GROUP_ID)
print(f"GROUP_ID={GROUP_ID}")

with open('key.der', 'wb') as handle:
    handle.write(der)
