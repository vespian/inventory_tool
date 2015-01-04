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
from inventory_tool.object.ippool import IPPool
from inventory_tool.exception import GenericException, MalformedInputException

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
        self._network_str = "172.21.243.0/28"
        self._network_obj = ip_network(self._network_str)
        self._allocated_str = ["172.21.243.1",
                               "172.21.243.2",
                               "172.21.243.6",
                               ]
        self._allocated_obj = [ip_address(x) for x in self._allocated_str]
        self._reserved_str = ["172.21.243.4",
                              "172.21.243.5",
                              ]
        self._reserved_obj = [ip_address(x) for x in self._reserved_str]

        self.ippool_obj = IPPool(network=self._network_str,
                                 allocated=self._allocated_str,
                                 reserved=self._reserved_str
                                 )


class TestIPPoolToString(TestIPPoolBase):
    def test_to_string_with_data(self):
        correct_str = \
"""Network: 172.21.243.0/28
Allocated:
\t- 172.21.243.1
\t- 172.21.243.2
\t- 172.21.243.6
Reserved:
\t- 172.21.243.4
\t- 172.21.243.5
"""
        self.assertEqual(correct_str, str(self.ippool_obj))

    def test_to_string_without_data(self):
        obj = IPPool(network=self._network_str)
        correct_str = \
"""Network: 172.21.243.0/28
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


class TestIPPoolContains(TestIPPoolBase):
    def test_contains_str(self):
        self.assertTrue(self._allocated_str[0] in self.ippool_obj)

    def test_not_contains_str(self):
        self.assertFalse("1.2.3.4" in self.ippool_obj)

    def test_contains_obj(self):
        self.assertTrue(self._allocated_obj[0] in self.ippool_obj)

    def test_not_contains_obj(self):
        self.assertFalse(ip_address("1.2.3.4") in self.ippool_obj)

    def test_unrelated_object(self):
        with self.assertRaises(MalformedInputException):
            ip_network("1.2.3.0/24") in self.ippool_obj

    def test_overlaps_if_overlaps(self):
        other = IPPool("172.21.0.0/16")
        self.assertTrue(self.ippool_obj.overlaps(other))

    def test_overlaps_if_does_not_overlaps(self):
        other = IPPool("1.2.0.0/16")
        self.assertFalse(self.ippool_obj.overlaps(other))


class TestIPPoolBooking(TestIPPoolBase):
    def test_booking_new(self):
        ip = "172.21.243.3"
        self.ippool_obj.book(ip_address(ip))
        correct_hash = {"network": self._network_str,
                        "allocated": sorted(self._allocated_str),
                        "reserved": sorted(self._reserved_str + [ip]),
                        }
        self.assertEqual(correct_hash, self.ippool_obj.get_hash())

    def test_booking_existing(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.book(self._reserved_obj[0])

    def test_booking_not_in_the_network(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.book(ip_address("1.2.3.4"))

    def test_cancel_existing(self):
        self.ippool_obj.cancel(self._reserved_obj[0])
        correct_hash = {"network": self._network_str,
                        "allocated": sorted(self._allocated_str),
                        "reserved": sorted(self._reserved_str[1:]),
                        }
        self.assertEqual(correct_hash, self.ippool_obj.get_hash())

    def test_cancel_not_booked_yet(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.cancel(ip_address("172.21.243.3"))

    def test_cancel_not_in_the_network(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.cancel(ip_address("1.2.3.4"))


class TestIPPoolAllocation(TestIPPoolBase):
    def test_release_all(self):
        self.ippool_obj.release_all()
        correct_hash = {"network": self._network_str,
                        "allocated": [],
                        "reserved": sorted(self._reserved_str),
                        }
        self.assertEqual(correct_hash, self.ippool_obj.get_hash())

    def test_release_existing(self):
        self.ippool_obj.release(self._allocated_obj[0])
        correct_hash = {"network": self._network_str,
                        "allocated": sorted(self._allocated_str[1:]),
                        "reserved": sorted(self._reserved_str),
                        }
        self.assertEqual(correct_hash, self.ippool_obj.get_hash())

    def test_release_non_allocated(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.release(ip_address("172.21.243.3"))

    def test_release_outside_of_network(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.release(ip_address("1.2.3.32"))

    def test_allocate_outside_of_network(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.allocate(ip_address("1.2.3.32"))

    def test_allocate_already_allocated(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.allocate(self._allocated_obj[0])

    def test_allocate_already_reserved(self):
        with self.assertRaises(MalformedInputException):
            self.ippool_obj.allocate(self._reserved_obj[0])

    def test_allocate_OK(self):
        ip = "172.21.243.3"
        self.ippool_obj.allocate(ip_address(ip))
        correct_hash = {"network": self._network_str,
                        "allocated": sorted(self._allocated_str + [ip]),
                        "reserved": sorted(self._reserved_str),
                        }
        self.assertEqual(correct_hash, self.ippool_obj.get_hash())

    def test_autoallocate_OK(self):
        self.ippool_obj.allocate()
        tmp = self.ippool_obj.get_hash()
        number_of_allocated = len(tmp['allocated'])
        self.assertEqual(len(self._allocated_str) + 1, number_of_allocated)

    def test_autoallocate_exhaust_ippool(self):
        for i in range(0, 16 - (len(self._allocated_str) + len(self._reserved_str) + 2)):
            self.ippool_obj.allocate()
        with self.assertRaises(GenericException):
            self.ippool_obj.allocate()
