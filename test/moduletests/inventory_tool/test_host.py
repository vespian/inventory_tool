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
from inventory_tool.object.host import Host
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


class TestHostBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        KeyWordValidator.set_extra_ipnetwork_keywords(["ipnetwork_var"])
        KeyWordValidator.set_extra_integer_keywords(["integer_var"])
        HostnameParser.set_backend_domain("test.domain.org")

    def setUp(self):
        self._aliases = ['test.example.com', 'other.domain.net']
        self._keyvals_plain = {"ansible_ssh_host": "1.2.3.4",
                               "some_var": "some_val",
                               "integer_var": 1234,
                               "ipnetwork_var": "1.2.3.0/24",
                               }
        self._keyvals_obj = self._keyvals_plain.copy()
        self._keyvals_obj['ansible_ssh_host'] = \
            ip_address(self._keyvals_obj['ansible_ssh_host'])
        self._keyvals_obj['ipnetwork_var'] = \
            ip_network(self._keyvals_obj['ipnetwork_var'])


class TestHostMethodsBase(TestHostBase):
    def setUp(self):
        super().setUp()
        self.host_obj = Host(aliases=self._aliases, keyvals=self._keyvals_plain)


class TestHostInitalization(TestHostBase):
    def test_correct_init(self):
        Host(aliases=self._aliases, keyvals=self._keyvals_plain)

    def test_malformed_init_args(self):
        with self.assertRaises(BadDataException):
            self.host_obj = Host(keyvals={"ansible_ssh_host": "not-an-ip"})


class TestHostToString(TestHostMethodsBase):
    def test_to_string_with_data(self):
        correct_str = \
"""Aliases:
\t- other.domain.net
\t- test.example.com
Host variables:
\tansible_ssh_host:1.2.3.4
\tinteger_var:1234
\tipnetwork_var:1.2.3.0/24
\tsome_var:some_val
"""
        self.assertEqual(correct_str, str(self.host_obj))

    def test_to_string_without_data(self):
        obj = Host()
        correct_str = \
"""Aliases:
\t<None>
Host variables:
\t<None>
"""
        self.assertEqual(correct_str, str(obj))


class TestHostGetHash(TestHostMethodsBase):
    def test_get_hash(self):
        correct_hash = {"aliases": sorted(self._aliases), "keyvals": self._keyvals_plain}
        helpers.stringify(correct_hash)
        self.assertEqual(correct_hash, self.host_obj.get_hash())


class TestHostKeyVal(TestHostMethodsBase):
    def test_get_existing_keyval(self):
        self.assertEqual("some_val", self.host_obj.get_keyval("some_var"))

    def test_get_missing_keyval(self):
        with self.assertRaises(MalformedInputException):
            self.host_obj.get_keyval("missing_var")

    def test_get_missing_keyval_noreporting(self):
        self.assertIsNone(self.host_obj.get_keyval("missing_var",
                                                   reporting=False))

    def test_get_all_keyvals(self):
        correct_hash = self._keyvals_obj
        correct_hash['aliases'] = self._aliases
        self.assertEqual(correct_hash, self.host_obj.get_keyval())

    def test_get_aliases(self):
        self.assertEqual(self._aliases, self.host_obj.get_keyval('aliases'))

    def test_set_keyval(self):
        data = {"key": "integer_var", "val": 15151512351}
        self.host_obj.set_keyval(data)
        self.assertEqual(data["val"], self.host_obj.get_keyval(data["key"]))

    def test_del_existing_keyval(self):
        self.host_obj.del_keyval("integer_var")
        with self.assertRaises(MalformedInputException):
            self.host_obj.get_keyval("integer_var")

    def test_del_missing_keyval(self):
        with self.assertRaises(MalformedInputException):
            self.host_obj.del_keyval("missing_var")


class TestHostAlias(TestHostMethodsBase):
    def test_get_all_aliases(self):
        self.assertEqual(self._aliases, self.host_obj.get_aliases())

    def test_get_existing_alias(self):
        self.assertEqual(self._aliases[0], self.host_obj.get_aliases(self._aliases[0]))

    def test_get_missing_alias_with_reporting(self):
        alias = 'missing.net'
        with self.assertRaises(MalformedInputException):
            self.assertEqual(alias, self.host_obj.get_aliases(alias))

    def test_get_missing_alias_without_reporting(self):
        self.assertIsNone(self.host_obj.get_aliases('missing.net', reporting=False))

    def test_existing_alias_add(self):
        with self.assertRaises(MalformedInputException):
            self.host_obj.alias_add(self._aliases[0])

    def test_new_alias_add(self):
        alias = "some.new.alias.net"
        self.host_obj.alias_add(alias)
        self.assertEqual(self._aliases + [alias, ], self.host_obj.get_aliases())

    def test_existing_alias_del(self):
        self.host_obj.alias_del(self._aliases[-1])
        self.assertEqual(self._aliases[:-1], self.host_obj.get_aliases())

    def test_missing_alias_del(self):
        with self.assertRaises(MalformedInputException):
            self.host_obj.alias_del("missing.alias.net")
