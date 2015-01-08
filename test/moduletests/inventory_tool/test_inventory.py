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
from mock import call
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
            raise FileNotFoundError
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


class TestInventoryRecalculation(TestInventoryBase):
    pass

class TestInventoryGroupFunctionality(TestInventoryBase):
    pass

class TestInventoryHostFunctionality(TestInventoryBase):
    pass

class TestInventoryIPPoolFunctionality(TestInventoryBase):
    pass

