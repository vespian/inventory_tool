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
import sys
import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import file_paths as paths
from inventory_tool.object.inventory import InventoryData
from inventory_tool.exception import MalformedInputException, BadDataException


class TestInventoryBase(unittest.TestCase):

    _ipaddr_keywords = ['ansible_ssh_host', 'tunnel_ip', 'var_without_pool']
    _ipnetwork_keywords = []

    def _normalization_func(self, hostname):
        if hostname == "foobarator.y1.example.com":
            return "foobarator.y1"
        elif hostname == 'gulgulator.example.com':
            return 'gulgulator'
        elif hostname == 'other.example.com':
            return 'other'
        elif hostname == 'y1-front.foobar.example.com':
            return 'y1-front.foobar'
        else:
            return hostname

    @classmethod
    def setUpClass(cls):
        with open(paths.TEST_INVENTORY, 'r') as fh:
            cls._file_data = fh.read()

    def setUp(self):
        self.mocks = {}
        for patched in ['logging.debug',
                        'logging.error',
                        'logging.info',
                        'logging.warning',
                        'inventory_tool.validators.HostnameParser',
                        'inventory_tool.validators.KeyWordValidator',
                        ]:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)



        self.mocks['inventory_tool.validators.KeyWordValidator'].get_ipaddress_keywords.return_value = \
            self._ipaddr_keywords
        self.mocks['inventory_tool.validators.KeyWordValidator'].get_ipnetwork_keywords.return_value = \
            self._ipnetwork_keywords
        self.mocks['inventory_tool.validators.KeyWordValidator'].is_ipaddress_keyword.side_effect = \
            lambda x: x in self._ipaddr_keywords
        self.mocks['inventory_tool.validators.KeyWordValidator'].is_ipnetwork_keyword.side_effect = \
            lambda x: x in self._ipnetwork_keywords
        self.mocks['inventory_tool.validators.HostnameParser'].normalize_hostname.side_effect = \
            self._normalization_func


class TestInventoryInit(TestInventoryBase):
    def setUp(self):
        super().setUp()
        for patched in ['inventory_tool.object.ippool.IPPool',
                        'inventory_tool.object.host.Host',
                        'inventory_tool.object.group.Group',
                        ]:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)

    def test_inventory_init(self):
        empty_inventory = {'_meta': {'hostvars': {}},
                           'all': {'children': [],
                                   'hosts': [],
                                   'vars': {}}}
        OpenMock = mock.mock_open(read_data=self._file_data)
        with mock.patch('__main__.open', OpenMock, create=True):
            obj = InventoryData(paths.TEST_INVENTORY, initialize=True)

        self.assertFalse(OpenMock.called)
        self.assertEqual(empty_inventory, obj.get_ansible_inventory())

    def test_inventory_file_missing(self):
        OpenMock = mock.mock_open(read_data=self._file_data)

        def raise_not_found(*unused):
            try:
                error_to_catch = FileNotFoundError
            except NameError:
                # Python < 3.4
                error_to_catch = IOError
            raise error_to_catch
        OpenMock.side_effect = raise_not_found
        with self.assertRaises(MalformedInputException):
            with mock.patch('inventory_tool.object.inventory.open', OpenMock,
                            create=True):
                InventoryData(paths.TEST_INVENTORY)

    def test_load_unsupported_file_format(self):
        data = self._file_data
        data = data.replace('version: 1', "version: 0")
        OpenMock = mock.mock_open(read_data=data)
        with self.assertRaises(BadDataException):
            with mock.patch('inventory_tool.object.inventory.open', OpenMock,
                            create=True):
                InventoryData(paths.TEST_INVENTORY)

    @mock.patch("inventory_tool.object.inventory.InventoryData.recalculate_inventory")
    def test_load_bad_checksum(self, RecalculateInventoryMock):
        # mock out inventory recalculation
        data = self._file_data
        data = data.replace('6119b68e3bc8d569568a93', '6119b68e3bc8d569568a16')
        OpenMock = mock.mock_open(read_data=data)
        with mock.patch('inventory_tool.object.inventory.open', OpenMock,
                        create=True):
            InventoryData(paths.TEST_INVENTORY)

        RecalculateInventoryMock.assert_called_with()

    def test_load_file_ok(self):
        OpenMock = mock.mock_open(read_data=self._file_data)

        with mock.patch('inventory_tool.object.inventory.open', OpenMock,
                        create=True):
            InventoryData(paths.TEST_INVENTORY)

        OpenMock.assert_called_once_with(paths.TEST_INVENTORY, 'rb')
        proper_ippool_calls = [call(network='192.168.125.0/24',
                                    reserved=['192.168.125.1'],
                                    allocated=['192.168.125.2', '192.168.125.3']),
                               call(network='192.168.255.0/24',
                                    reserved=[],
                                    allocated=['192.168.255.125'])]
        self.mocks['inventory_tool.object.ippool.IPPool'].assert_has_calls(
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
        self.mocks['inventory_tool.object.group.Group'].assert_has_calls(
            proper_group_calls, any_order=True)
        proper_host_calls = [call(keyvals={'ansible_ssh_host': '1.2.3.4',
                                           'tunnel_ip': '192.168.255.125'},
                                  aliases=[]),
                             call(keyvals={'ansible_ssh_host': '192.168.125.3'},
                                  aliases=[]),
                             call(keyvals={'ansible_ssh_host': '192.168.125.2'},
                                  aliases=['front-foobar.y1'])]
        self.mocks['inventory_tool.object.host.Host'].assert_has_calls(
            proper_host_calls, any_order=True)


class TestInventorySave(TestInventoryBase):
    def test_save_file(self):
        OpenMock = mock.mock_open(read_data=self._file_data)
        with mock.patch('inventory_tool.object.inventory.open', OpenMock, create=True):
            obj = InventoryData(paths.TMP_INVENTORY)

        SaveMock = mock.mock_open()
        with mock.patch('inventory_tool.object.inventory.open', SaveMock, create=True):
            obj.save()
        SaveMock.assert_called_once_with(paths.TMP_INVENTORY, 'wb')
        # Comparing multi-line text is tricky:
        handle = SaveMock()
        self.maxDiff = None
        self.assertMultiLineEqual(self._file_data, handle.write.call_args[0][0])


class TestInventoryAnsibleFuncionality(TestInventoryBase):
    def test_missing_ansible_ssh_host(self):
        obj = InventoryData(paths.MISSING_ANSIBLE_SSH_HOST_INVENTORY)
        with self.assertRaises(BadDataException):
            obj.get_ansible_inventory()

    def test_get_ansible_inventory(self):
        self.maxDiff = None
        OpenMock = mock.mock_open(read_data=self._file_data)
        with mock.patch('inventory_tool.object.inventory.open', OpenMock, create=True):
            obj = InventoryData(paths.TMP_INVENTORY)
        correct_data = {'_meta': {'hostvars': {'foobarator.y1': {'aliases': [],
                                                                 'ansible_ssh_host': '192.168.125.3'},
                                               'y1': {'aliases': [],
                                                      'ansible_ssh_host': '1.2.3.4',
                                                      'tunnel_ip': '192.168.255.125'},
                                               'y1-front.foobar': {'aliases': ['front-foobar.y1'],
                                                                   'ansible_ssh_host': '192.168.125.2'}}},
                        'all': {'children': [],
                                'hosts': ['foobarator.y1', 'y1', 'y1-front.foobar'],
                                'vars': {}},
                        'front': {'children': [],
                                  'hosts': ['y1-front.foobar'],
                                  'vars': {}},
                        'guests-y1': {'children': [],
                                      'hosts': ['foobarator.y1', 'y1-front.foobar'],
                                      'vars': {}},
                        'hypervisor': {'children': [],
                                       'hosts': ['y1'],
                                       'vars': {}}}

        test_data = obj.get_ansible_inventory()

        self.assertEqual(test_data, correct_data)


class TestInventoryRecalculation(TestInventoryBase):
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

    def test_is_recalculated_flag(self):
        obj = InventoryData(paths.EMPTY_CHECKSUM_OK_INVENTORY)
        self.assertFalse(obj.is_recalculated())
        obj = InventoryData(paths.EMPTY_CHECKSUM_BAD_INVENTORY)
        self.assertTrue(obj.is_recalculated())

    def test_hosts_cleanup(self):
        obj = InventoryData(paths.ORPHANED_HOSTS_INVENTORY)
        obj.recalculate_inventory()
        front_hosts = obj.group_get("front").get_hosts()
        guests_y1_hosts = obj.group_get("guests-y1").get_hosts()
        hypervisor_hosts = obj.group_get("hypervisor").get_hosts()
        self.assertListEqual(guests_y1_hosts, ['foobarator.y1', 'y1-front.foobar'])
        self.assertListEqual(front_hosts, ['y1-front.foobar'])
        self.assertListEqual(hypervisor_hosts, ['y1'])

    @mock.patch('inventory_tool.object.inventory.InventoryData.host_rename')
    def test_hostname_normalization(self, HostRenameMock):
        obj = InventoryData(paths.DENORMALIZED_HOSTNAMES_INVENTORY)
        obj.recalculate_inventory()
        HostRenameMock.assert_called_once_with('foobarator.y1.example.com',
                                               'foobarator.y1')

    def test_alias_normalization(self):
        obj = InventoryData(paths.DENORMALIZED_ALIASES_INVENTORY)
        obj.recalculate_inventory()
        foobarator_aliases = obj.host_get("foobarator.y1").get_aliases()
        y1_aliases = obj.host_get("y1").get_aliases()
        y1_front_aliases = obj.host_get("y1-front.foobar").get_aliases()
        self.assertListEqual(foobarator_aliases,
                             ['proper', 'gulgulator', 'other'])
        self.assertListEqual(y1_aliases, ["other-proper"])
        self.assertListEqual(y1_front_aliases, [])


class TestInventoryHostFunctionality(TestInventoryBase):
    def setUp(self):
        super().setUp()
        OpenMock = mock.mock_open(read_data=self._file_data)
        with mock.patch('inventory_tool.object.inventory.open', OpenMock, create=True):
            self.obj = InventoryData(paths.TMP_INVENTORY)


class TestInventoryHostMiscFunctionality(TestInventoryHostFunctionality):
    def test_host_to_groups(self):
        calculated_groups = self.obj.host_to_groups("y1-front.foobar")
        self.assertCountEqual(['guests-y1', 'front'], calculated_groups)
        calculated_groups = self.obj.host_to_groups("bulbulator")
        self.assertListEqual([], calculated_groups)

    def test_inexistant_host_rename_mock(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_rename("bulbulator", "new-bulbulator")

    def test_normalized_host_rename(self):
        self.obj.host_rename("y1-front.foobar", "y1-lorem.ipsum")

        with self.assertRaises(MalformedInputException):
            self.obj.host_get("y1-front.foobar")

        host_hash = self.obj.host_get("y1-lorem.ipsum").get_hash()
        correct_hash = {'aliases': ['front-foobar.y1'],
                        'keyvals': {'ansible_ssh_host': '192.168.125.2'}
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_denormalized_host_rename(self):
        self.obj.host_rename("y1-front.foobar", "gulgulator.example.com")

        with self.assertRaises(MalformedInputException):
            self.obj.host_get("y1-front.foobar")

        host_hash = self.obj.host_get("gulgulator").get_hash()
        correct_hash = {'aliases': ['front-foobar.y1'],
                        'keyvals': {'ansible_ssh_host': '192.168.125.2'}
                        }
        self.assertEqual(host_hash, correct_hash)


class TestInventoryHostAliasFunctionality(TestInventoryHostFunctionality):
    def test_delete_normalized_alias(self):
        self.obj.host_alias_del("y1-front.foobar", 'front-foobar.y1')
        host_hash = self.obj.host_get("y1-front.foobar").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '192.168.125.2'}
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_delete_denormalized_alias(self):
        self.obj.host_alias_del("y1-front.foobar.example.com", 'front-foobar.y1')
        host_hash = self.obj.host_get("y1-front.foobar").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '192.168.125.2'}
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_delete_missing_alias(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_alias_del("foo-bar", 'foobarator')

    def test_add_alias_to_missing_host(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_alias_add("foo-bar", 'foobarator')

    def test_add_alias_that_duplicates_host(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_alias_add("foobarator.y1", 'y1')

    def test_add_alias_that_duplicates_other_alias(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_alias_add("foobarator.y1", 'front-foobar.y1')

    def test_add_alias(self):
        self.obj.host_alias_add("foobarator.y1", "some-alias.y1")
        host_hash = self.obj.host_get("foobarator.y1").get_hash()
        correct_hash = {'aliases': ['some-alias.y1'],
                        'keyvals': {'ansible_ssh_host': '192.168.125.3'}
                        }
        self.assertEqual(host_hash, correct_hash)


class TestInventoryHostKeyvalFunctionality(TestInventoryHostFunctionality):
    def test_plain_keyval_removal(self):
        # FIXME - this can be done without introducing another fabric file,
        # but hosts-production needs to be changed and with it a lot of tests.
        obj = InventoryData(paths.HOSTVARS_INVENTORY)
        obj.host_del_vars('foobarator.y1',
                          ['some_key'])

        host_hash = obj.host_get("foobarator.y1").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '192.168.125.3',
                                    "some_other_key": "12345"
                                    }
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_plain_keyval_removal_from_missing_host(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_del_vars("lorem-ipsum", 'some_keyval')

    def test_plain_keyval_removal_which_does_not_exists(self):
        obj = InventoryData(paths.HOSTVARS_INVENTORY)
        with self.assertRaises(MalformedInputException):
            self.obj.host_del_vars('foobarator.y1',
                                   ['some_key', 'inexistant_keyval'])

        # Other keyvals should not be removed if at least one keyval does not
        # exists:
        host_hash = obj.host_get("foobarator.y1").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '192.168.125.3',
                                    'some_key': 'some_val',
                                    "some_other_key": "12345"
                                    }
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_plain_keyval_set(self):
        self.obj.host_set_vars('y1', [{"key": 'some_keyval', "val": "some_val"}])

        host_hash = self.obj.host_get("y1").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '1.2.3.4',
                                    'tunnel_ip': '192.168.255.125',
                                    'some_keyval': "some_val"
                                    }
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_plain_keyval_set_for_inexistant_host(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_set_vars("lorem-ipsum", [{"key": 'some_keyval',
                                                   "val": "some_val"}])

    def test_ipaddr_keyval_removal(self):
        self.obj.host_del_vars('y1',
                               ['tunnel_ip'])

        # Check if keyval was removed:
        host_hash = self.obj.host_get("y1").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '1.2.3.4',
                                    }
                        }
        self.assertEqual(host_hash, correct_hash)

        # And if it was deallocated:
        ippool_hash = self.obj.ippool_get("tunels").get_hash()
        self.assertListEqual([], ippool_hash['allocated'])

    def test_ipaddr_keyval_set_without_autoallocation(self):
        self.obj.host_set_vars('foobarator.y1', [{"key": 'tunnel_ip', "val": "1.2.3.20"}])

        host_hash = self.obj.host_get("foobarator.y1").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '192.168.125.3',
                                    'tunnel_ip': '1.2.3.20',
                                    }
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_ipaddr_keyval_set_with_autoallocation(self):
        obj = InventoryData(paths.IPADDR_AUTOALLOCATION_INVENTORY)
        obj.host_set_vars('y1-front.foobar', [{"key": 'tunnel_ip', "val": None}])

        host_hash = obj.host_get("y1-front.foobar").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'tunnel_ip': '192.168.255.1'}
                        }
        self.assertEqual(host_hash, correct_hash)

    def test_ipaddr_keyval_set_with_broken_autoallocation(self):
        with self.assertRaises(MalformedInputException):
            self.obj.host_set_vars('foobarator.y1', [{"key": 'var_without_pool',
                                                      "val": None}])

    def test_ipaddr_keyval_change_without_autoallocation(self):
        self.obj.host_set_vars('y1', [{"key": 'tunnel_ip', "val": "192.168.255.123"}])

        # Check if keyval was removed:
        host_hash = self.obj.host_get("y1").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '1.2.3.4',
                                    'tunnel_ip': '192.168.255.123',
                                    }
                        }
        self.assertEqual(host_hash, correct_hash)
        ippool_hash = self.obj.ippool_get("tunels").get_hash()
        self.assertListEqual(ippool_hash['allocated'], ["192.168.255.123"])

    def test_ipaddr_keyval_change_with_autoallocation(self):
        self.obj.host_set_vars('y1', [{"key": 'tunnel_ip', "val": None}])

        # Check if keyval was removed:
        host_hash = self.obj.host_get("y1").get_hash()
        correct_hash = {'aliases': [],
                        'keyvals': {'ansible_ssh_host': '1.2.3.4',
                                    'tunnel_ip': '192.168.255.1',
                                    }
                        }
        self.assertEqual(host_hash, correct_hash)
        ippool_hash = self.obj.ippool_get("tunels").get_hash()
        self.assertListEqual(ippool_hash['allocated'], ["192.168.255.1"])




class TestInventoryGroupFunctionality(TestInventoryBase):
    pass


class TestInventoryIPPoolFunctionality(TestInventoryBase):
    pass
