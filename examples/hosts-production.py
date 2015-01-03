#!/usr/bin/env python3

# Copyright (c) 2014 Pawel Rozlach, Brainly.com sp. z o.o.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

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
import inventory_tool.cmdline as cmd

# Locate the inventory file:
name = op.basename(sys.argv[0]).split(".")[0] + ".yml"
inventory_path = op.abspath(op.join(cwd, inventory_path, name))

if __name__ == '__main__':
    cmd.main(sys.argv,
             inventory_path,
             backend_domain=backend_domain,
             extra_ipaddress_keywords=ipaddress_keywords,
             extra_ipnetwork_keywords=ipnetwork_keywords,
             )
