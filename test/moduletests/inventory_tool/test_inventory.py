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
import os
import sys
import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import helpers
from inventory_tool.object.inventory import InventoryData
from inventory_tool.exception import BadDataException, MalformedInputException


class TestInventoryBase(unittest.TestCase):
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
                        'logging.warn', ]:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)

class TestInventoryInit(TestInventoryBase):
    def setUp(self):
        # load config from file and mock it
        # then change only particular fields
        pass

    def test_inventory_init(self):
        pass

    def test_inventory_file_missing(self):
        pass

    def test_load_unsupported_file_format(self):
        pass

    def test_load_bad_checksum(self):
        # mock out inventory recalculation
        pass

    def test_load_file_ok(self):
        pass

class TestInventoryGroupFunctionality(TestInventoryBase):
    pass

class TestInventoryHostFunctionality(TestInventoryBase):
    pass

class TestInventoryIPPoolFunctionality(TestInventoryBase):
    pass

