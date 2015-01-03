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
import mock
import sys
import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
from inventory_tool.object.group import Group
from inventory_tool.cmdline import HostnameParser
from inventory_tool.exception import MalformedInputException


class TestGroupBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        HostnameParser.set_backend_domain("test.domain.org")

    def setUp(self):
        self._hosts = ['hostA', 'hostB', 'hostC', ]
        self._children = ['groupA', 'groupB', 'groupC', 'groupD']
        self._ippools = {'varA': 'poolZ',
                         'varB': 'poolY', }

        self.group_obj = Group(hosts=self._hosts,
                               children=self._children,
                               ippools=self._ippools
                               )


class TestGroupToString(TestGroupBase):
    def test_to_string_with_data(self):
        correct_str = \
"""Hosts:
\t- hostA
\t- hostB
\t- hostC
Children:
\t- groupA
\t- groupB
\t- groupC
\t- groupD
Ip pools:
\tvarA:poolZ
\tvarB:poolY
"""
        self.assertEqual(correct_str, str(self.group_obj))

    def test_to_string_without_data(self):
        obj = Group()
        correct_str = \
"""Hosts:
\t<None>
Children:
\t<None>
Ip pools:
\t<None>
"""
        self.assertEqual(correct_str, str(obj))


class TestGroupGetHash(TestGroupBase):
    def test_get_hash(self):
        correct_hash = {"hosts": sorted(self._hosts),
                        "children": sorted(self._children),
                        "ippools": self._ippools
                        }
        self.assertEqual(correct_hash, self.group_obj.get_hash())


class TestGroupChild(TestGroupBase):
    def test_has_existing_child(self):
        self.assertTrue(self.group_obj.has_child(self._children[0]))

    def test_has_missing_child(self):
        self.assertFalse(self.group_obj.has_child("missing.child"))

    def test_get_all_children(self):
        self.assertEqual(self._children, self.group_obj.get_children())

    def test_add_new_child(self):
        child = 'a-new-child'
        self.group_obj.add_child(child)
        self.assertEqual(self._children + [child], self.group_obj.get_children())

    def test_add_existing_child(self):
        with self.assertRaises(MalformedInputException):
            self.group_obj.add_child(self._children[0])

    def test_del_missing_child_with_reporting(self):
        with self.assertRaises(MalformedInputException):
            self.group_obj.del_child('a-missing-child')

    def test_del_missing_child_without_reporting(self):
        self.assertIsNone(self.group_obj.del_child('a-missing-child',
                                                   reporting=False))

    def test_del_existing_child(self):
        self.group_obj.del_child(self._children[-1])
        self.assertEqual(self._children[:-1], self.group_obj.get_children())


class TestGroupHost(TestGroupBase):
    def test_has_existing_host(self):
        self.assertTrue(self.group_obj.has_host(self._hosts[0]))

    def test_has_missing_host(self):
        self.assertFalse(self.group_obj.has_host("missing.host"))

    def test_get_hosts(self):
        self.assertEqual(self._hosts, self.group_obj.get_hosts())

    def test_add_new_host(self):
        host = 'a-new-host'
        self.group_obj.add_host(host)
        self.assertEqual(self._hosts + [host], self.group_obj.get_hosts())

    def test_add_existing_host(self):
        with self.assertRaises(MalformedInputException):
            self.group_obj.add_host(self._hosts[0])

    def test_del_missing_host_with_reporting(self):
        with self.assertRaises(MalformedInputException):
            self.group_obj.del_host('a-missing-host')

    def test_del_missing_host_without_reporting(self):
        self.assertIsNone(self.group_obj.del_host('a-missing-host',
                                                  reporting=False))

    def test_del_existing_host(self):
        self.group_obj.del_host(self._hosts[-1])
        self.assertEqual(self._hosts[:-1], self.group_obj.get_hosts())


@mock.patch('logging.warn')
@mock.patch('logging.info')
@mock.patch('logging.error')
class TestGroupIPPool(TestGroupBase):
    def test_get_ippool_existing(self, *unused):
        self.assertEqual(self._ippools['varA'], self.group_obj.get_pool('varA'))

    def test_get_ippool_missing(self, *unused):
        self.assertIsNone(self.group_obj.get_pool('not-a-pool'))

    def test_set_pool(self, *unused):
        self.group_obj.set_pool('newVar', 'newPool')
        self.assertEqual('newPool', self.group_obj.get_pool('newVar'))

    def test_del_pool_by_var(self, *unused):
        self.group_obj.del_pool_by_var('varA')
        self.assertIsNone(self.group_obj.get_pool('varA'))

    def test_del_pool_by_pool_existing(self, *unused):
        self.group_obj.del_pool_by_pool('poolY')
        self.assertIsNone(self.group_obj.get_pool('varB'))
