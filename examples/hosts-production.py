#!/usr/bin/env python3

# (c) 2014 Brainly.com, Pawel Rozlach <pawel.rozlach@brainly.com>

# This script is intended to only find "where it is" and invoke the inventory
# tool with correct inventory path basing on it's name.

import os.path as op
import sys

# Configuration:
backend_domain = 'example.com'
ipaddress_keywords = ["tunnel_ip", ]
ipnetwork_keywords = []
inventorytool_path = '..'
inventory_path = '../test/fabric/'

# Where am I ?
cwd = op.dirname(op.realpath(__file__))

# Import inventory_tool
if inventorytool_path is not None:
    sys.path.insert(0, op.abspath(op.join(cwd, inventorytool_path)))
import inventory_tool

# Locate the inventory file:
name = op.basename(sys.argv[0]).split(".")[0] + ".yml"
inventory_path = op.abspath(op.join(cwd, inventory_path, name))

if __name__ == '__main__':
    inventory_tool.main(sys.argv,
                        inventory_path,
                        backend_domain=backend_domain,
                        extra_ipaddress_keywords=ipaddress_keywords,
                        extra_ipnetwork_keywords=ipnetwork_keywords,
                        )
