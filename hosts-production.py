#!/usr/bin/env python3

# (c) 2014 Brainly.com, Pawel Rozlach <pawel.rozlach@brainly.com>

# This script is intended to only find "where it is" and invoke the inventory
# tool with correct inventory path basing on it's name.

import os.path as op
import sys
import tools.inventory_tool

# Configuration:
backend_domain = 'example.com'
ipaddress_keywords = ["tunnel_ip", ]
ipnetwork_keywords = []

if __name__ == '__main__':
    # Where am I ?
    cwd = op.dirname(op.realpath(__file__))

    # Where is the data ?
    name = op.basename(sys.argv[0]).split(".")[0] + ".yml"
    inventory_path = op.join(cwd, "data", "inventory", name)

    # Go!
    tools.inventory_tool.main(sys.argv,
                              inventory_path,
                              backend_domain=backend_domain,
                              extra_ipaddress_keywords=ipaddress_keywords,
                              extra_ipnetwork_keywords=ipnetwork_keywords,
                              )
