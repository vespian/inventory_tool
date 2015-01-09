#!/usr/bin/env python3
# Copyright (c) 2015 Brainly.com sp. z o.o.
# Copyright (c) 2014 Brainly.com sp. z o.o.
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
import mock
from mock import call, Mock
import os
import yaml
import sys
import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import helpers
import file_paths as paths
from inventory_tool.object.ippool import IPPool
from inventory_tool.object.inventory import InventoryData
from inventory_tool.exception import MalformedInputException, BadDataException, MalformedInputException


class TestInventoryBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(paths.TEST_INVENTORY, 'r') as fh:
            cls._file_data = fh.read()

    def setUp(self):
        self.mocks = {}
        for patched in ['inventory_tool.object.inventory.IPPool',
                        'inventory_tool.object.inventory.HostnameParser',
                        'inventory_tool.object.inventory.Host',
                        'inventory_tool.object.inventory.Group',
                        'inventory_tool.object.inventory.KeyWordValidator',
                        'logging.debug',
                        'logging.error',
                        'logging.info',
                        'logging.warning', ]:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)

class TestInventoryInit(TestInventoryBase):
    def test_inventory_init(self):
        empty_inventory = {'_meta': {'hostvars': {}},
                           'all': {'children': [],
                                   'hosts': [],
                                   'vars': {}}}
        OpenMock = mock.mock_open(read_data = self._file_data)
        with mock.patch('__main__.open', OpenMock, create=True):
            obj = InventoryData(paths.TEST_INVENTORY, initialize=True)

        self.assertFalse(OpenMock.called)
        self.assertEqual(empty_inventory, obj.get_ansible_inventory())

    def test_inventory_file_missing(self):
        OpenMock = mock.mock_open(read_data = self._file_data)
        def raise_not_found(*unused):
            try:
                error_to_catch = FileNotFoundError
            except NameError:
                # Python < 3.4
                error_to_catch = IOError
            raise error_to_catch
        OpenMock.side_effect = raise_not_found
        with self.assertRaises(MalformedInputException):
            with mock.patch('inventory_tool.object.inventory.open', OpenMock, create=True):
                obj = InventoryData(paths.TEST_INVENTORY)

    def test_load_unsupported_file_format(self):
        data = self._file_data
        data = data.replace('version: 1', "version: 0")
        OpenMock = mock.mock_open(read_data=data)
        with self.assertRaises(BadDataException):
            with mock.patch('inventory_tool.object.inventory.open', OpenMock, create=True):
                obj = InventoryData(paths.TEST_INVENTORY)

    @mock.patch("inventory_tool.object.inventory.InventoryData.recalculate_inventory")
    def test_load_bad_checksum(self, RecalculateInventoryMock):
        # mock out inventory recalculation
        data = self._file_data
        data = data.replace('ca9048976eb8c037685c516', 'ca9048976eb8c037685c000')
        OpenMock = mock.mock_open(read_data=data)
        with mock.patch('inventory_tool.object.inventory.open', OpenMock, create=True):
            InventoryData(paths.TEST_INVENTORY)

        RecalculateInventoryMock.assert_called_with()


    def test_load_file_ok(self):
        OpenMock = mock.mock_open(read_data=self._file_data)

        with mock.patch('inventory_tool.object.inventory.open', OpenMock, create=True):
            obj = InventoryData(paths.TEST_INVENTORY)

        OpenMock.assert_called_once_with(paths.TEST_INVENTORY, 'rb')
        proper_ippool_calls = [call(network='192.168.125.0/24',
                                    reserved=['192.168.125.1'],
                                    allocated=['192.168.125.2', '192.168.125.3']),
                               call(network='192.168.255.0/24',
                                    reserved=[],
                                    allocated=[]),]
        self.mocks['inventory_tool.object.inventory.IPPool'].assert_has_calls(
            proper_ippool_calls, any_order=True)
        proper_group_calls = [call(ippools={'tunnel_ip': 'tunels'},
                                   hosts=['y1'],
                                   children=[]),
                              call(ippools={},
                                   hosts=['y1-front.foobar'],
                                   children=[]),
                              call(ippools={'ansible_ssh_host': 'y1_guests'},
                                   hosts=['foobarator.y1', 'y1-front.foobar'],
                                   children=[])]
        self.mocks['inventory_tool.object.inventory.Group'].assert_has_calls(
            proper_group_calls, any_order=True)
        proper_host_calls = [call(keyvals={'ansible_ssh_host': '1.2.3.4',
                                           'tunnel_ip': '192.168.1.125'},
                                  aliases=[]),
                             call(keyvals={'ansible_ssh_host': '192.168.125.3'},
                                  aliases=[]),
                             call(keyvals={'ansible_ssh_host': '192.168.125.2'},
                                  aliases=['front-foobar.y1'])]
        self.mocks['inventory_tool.object.inventory.Host'].assert_has_calls(
            proper_host_calls, any_order=True)


class TestInventoryRecalculation(unittest.TestCase):
    def setUp(self):
        self.mocks = {}
        for patched in ['logging.debug',
                        'logging.error',
                        'logging.info',
                        'logging.warning',
                        'inventory_tool.object.inventory.HostnameParser',
                        'inventory_tool.object.inventory.KeyWordValidator', ]:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)

        self.mocks['inventory_tool.object.inventory.KeyWordValidator'].get_ipaddress_keywords.return_value = \
            ['ansible_ssh_host', 'tunnel_ip']
        self.mocks['inventory_tool.object.inventory.HostnameParser'].normalize_hostname = \
            lambda x: x

    def test_overlapping_ippools(self):
        obj = InventoryData(paths.OVERLAPPING_IPPOOLS_INVENTORY)

        with self.assertRaises(BadDataException):
            obj.recalculate_inventory()

    def test_nonoverlapping_ippools(self):
        obj = InventoryData(paths.NONOVERLAPPING_IPPOOLS_INVENTORY)

        obj.recalculate_inventory()

    
    def test_ippool_refresh(self):
        obj = InventoryData(paths.REFRESHED_IPPOOL_INVENTORY)
        obj.recalculate_inventory()
        y1_guests_pool_allocated = obj.ippool_get('y1_guests').get_hash()["allocated"]
        tunels_pool_allocated = obj.ippool_get('tunels').get_hash()["allocated"]
        correct_tunnels_pool_allocation = ['192.168.1.125']
        correct_y1_guests_pool_allocation = ['192.168.125.2', '192.168.125.3']
        self.assertListEqual(tunels_pool_allocated, correct_tunnels_pool_allocation)
        self.assertListEqual(y1_guests_pool_allocated, correct_y1_guests_pool_allocation)

    def test_child_groups_cleanup(self):
        obj = InventoryData(paths.ORPHANED_CHILD_GORUPS_INVENTORY)
        obj.recalculate_inventory()
        front_children = obj.group_get("front").get_children()
        guests_y1_children = obj.group_get("guests-y1").get_children()
        all_guests_children = obj.group_get("all-guests").get_children()
        all_children = obj.group_get("all").get_children()
        self.assertListEqual([], front_children)
        self.assertListEqual([], guests_y1_children)
        self.assertListEqual(['guests-y1'], all_guests_children)
        self.assertListEqual(['all-guests', 'front'], all_children)

    def test_hosts_cleanup(self):
        pass


class TestInventoryGroupFunctionality(TestInventoryBase):
    pass

class TestInventoryHostFunctionality(TestInventoryBase):
    pass

class TestInventoryIPPoolFunctionality(TestInventoryBase):
    pass

