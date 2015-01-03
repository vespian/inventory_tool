#!/usr/bin/env python3
# Copyright (c) 2014 Brainly.com sp. z o.o.
# Copyright (c) 2013 Spotify AB
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

# Global imports:
import os
import sys
import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import helpers
from inventory_tool.validators import KeyWordValidator
from inventory_tool.object.ippool import IPPool
from inventory_tool.cmdline import HostnameParser
from inventory_tool.exception import BadDataException, MalformedInputException

# For Python3 < 3.3, ipaddress module is available as an extra module,
# under a different name:
try:
    from ipaddress import ip_address
    from ipaddress import ip_network
except ImportError:
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPNetwork as ip_network


class TestIPPoolBase(unittest.TestCase):
    def setUp(self):
        self._network_str = "172.21.243.0/24"
        self._network_obj = ip_network(self._network_str)
        self._allocated_str = ["172.21.243.14",
                               "172.21.243.15",
                               "172.21.243.16",
                               "172.21.243.19",
                               ]
        self._allocated_obj = [ip_address(x) for x in self._allocated_str]
        self._reserved_str = ["172.21.243.214",
                               "172.21.243.215",
                               "172.21.243.216",
                               "172.21.243.219",
                               ]
        self._reserved_obj = [ip_address(x) for x in self._reserved_str]

        self.ippool_obj = IPPool(network=self._network_str,
                                 allocated=self._allocated_str,
                                 reserved=self._reserved_str
                                 )


class TestIPPoolToString(TestIPPoolBase):
    def test_to_string_with_data(self):
        correct_str = \
"""Network: 172.21.243.0/24
Allocated:
\t- 172.21.243.14
\t- 172.21.243.15
\t- 172.21.243.16
\t- 172.21.243.19
Reserved:
\t- 172.21.243.214
\t- 172.21.243.215
\t- 172.21.243.216
\t- 172.21.243.219
"""
        self.assertEqual(correct_str, str(self.ippool_obj))

    def test_to_string_without_data(self):
        obj = IPPool(network=self._network_str)
        data = str(obj)
        correct_str = \
"""Network: 172.21.243.0/24
Allocated:
\t<None>
Reserved:
\t<None>
"""
        self.assertEqual(correct_str, str(obj))


class TestIPPoolGetHash(TestIPPoolBase):
    def test_get_hash(self):
        correct_hash = {"network": self._network_str,
                        "allocated": sorted(self._allocated_str),
                        "reserved": sorted(self._reserved_str),
                        }
        self.assertEqual(correct_hash, self.ippool_obj.get_hash())


#class TestIPPoolKeyVal(TestIPPoolBase):
#    def test_get_existing_keyval(self):
#        self.assertEqual("some_val", self.ippool_obj.get_keyval("some_var"))
#
#    def test_get_missing_keyval(self):
#        with self.assertRaises(MalformedInputException):
#            self.ippool_obj.get_keyval("missing_var")
#
#    def test_get_missing_keyval_noreporting(self):
#        self.assertIsNone(self.ippool_obj.get_keyval("missing_var",
#                                                   reporting=False))
#
#    def test_get_all_keyvals(self):
#        correct_hash = self._keyvals_obj
#        correct_hash['aliases'] = self._aliases
#        self.assertEqual(correct_hash, self.ippool_obj.get_keyval())
#
#    def test_get_aliases(self):
#        self.assertEqual(self._aliases, self.ippool_obj.get_keyval('aliases'))
#
#    def test_set_keyval(self):
#        data = {"key": "integer_var", "val": 15151512351}
#        self.ippool_obj.set_keyval(data)
#        self.assertEqual(data["val"], self.ippool_obj.get_keyval(data["key"]))
#
#    def test_del_existing_keyval(self):
#        self.ippool_obj.del_keyval("integer_var")
#        with self.assertRaises(MalformedInputException):
#            self.ippool_obj.get_keyval("integer_var")
#
#    def test_del_missing_keyval(self):
#        with self.assertRaises(MalformedInputException):
#            self.ippool_obj.del_keyval("missing_var")
#
#
#class TestIPPoolAlias(TestIPPoolBase):
#    def test_get_all_aliases(self):
#        self.assertEqual(self._aliases, self.ippool_obj.get_aliases())
#
#    def test_get_existing_alias(self):
#        self.assertEqual(self._aliases[0], self.ippool_obj.get_aliases(self._aliases[0]))
#
#    def test_get_missing_alias_with_reporting(self):
#        alias = 'missing.net'
#        with self.assertRaises(MalformedInputException):
#            self.assertEqual(alias, self.ippool_obj.get_aliases(alias))
#
#    def test_get_missing_alias_without_reporting(self):
#        self.assertIsNone(self.ippool_obj.get_aliases('missing.net', reporting=False))
#
#    def test_existing_alias_add(self):
#        with self.assertRaises(MalformedInputException):
#            self.ippool_obj.alias_add(self._aliases[0])
#
#    def test_new_alias_add(self):
#        alias = "some.new.alias.net"
#        self.ippool_obj.alias_add(alias)
#        self.assertEqual(self._aliases + [alias, ], self.ippool_obj.get_aliases())
#
#    def test_existing_alias_del(self):
#        self.ippool_obj.alias_del(self._aliases[-1])
#        self.assertEqual(self._aliases[:-1], self.ippool_obj.get_aliases())
#
#    def test_missing_alias_del(self):
#        with self.assertRaises(MalformedInputException):
#            self.ippool_obj.alias_del("missing.alias.net")
