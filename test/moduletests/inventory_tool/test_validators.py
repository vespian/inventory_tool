#!/usr/bin/env python3
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
import argparse
import mock
import os
import sys
import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import inventory_tool.validators as v
from inventory_tool.exception import MalformedInputException

# For Python3 < 3.3, ipaddress module is available as an extra module,
# under a different name:
try:
    from ipaddress import ip_address
    from ipaddress import ip_network
except ImportError:
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPNetwork as ip_network


class TestKeyWordValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        v.KeyWordValidator.set_extra_ipaddress_keywords([])
        v.KeyWordValidator.set_extra_ipnetwork_keywords([])
        v.KeyWordValidator.set_extra_integer_keywords([])

    @classmethod
    def tearDownClass(cls):
        cls.setUpClass()

    def test_get_ipaddress_keywords(self):
        self.assertEqual(["ansible_ssh_host", ],
                         v.KeyWordValidator.get_ipaddress_keywords())

    def test_set_extra_ipaddress_keywords(self):
        keywords = ["ipaddr_keyword", "other_keyword"]
        v.KeyWordValidator.set_extra_ipaddress_keywords(keywords)
        self.assertEqual(["ansible_ssh_host"] + keywords,
                         v.KeyWordValidator.get_ipaddress_keywords())

    def test_is_ipaddress_keyword(self):
        self.assertTrue(v.KeyWordValidator.is_ipaddress_keyword("ansible_ssh_host"))

    def test_is_not_ipaddress_keyword(self):
        self.assertFalse(v.KeyWordValidator.is_ipaddress_keyword("some_keyword"))

    def test_get_ipnetwork_keywords(self):
        self.assertEqual([],
                         v.KeyWordValidator.get_ipnetwork_keywords())

    def test_set_ipnetwork_keyword(self):
        keywords = ["ipnet_keyword", "other_keyword"]
        v.KeyWordValidator.set_extra_ipnetwork_keywords(keywords)
        self.assertEqual(keywords,
                         v.KeyWordValidator.get_ipnetwork_keywords())

    def test_is_ipnetwork_keyword(self):
        keywords = ["ipnet_keyword", "other_keyword"]
        v.KeyWordValidator.set_extra_ipnetwork_keywords(keywords)
        self.assertTrue(v.KeyWordValidator.is_ipnetwork_keyword("ipnet_keyword"))

    def test_is_not_ipnetwork_keyword(self):
        keywords = ["ipnet_keyword", "other_keyword"]
        v.KeyWordValidator.set_extra_ipnetwork_keywords(keywords)
        self.assertFalse(v.KeyWordValidator.is_ipnetwork_keyword("some_keyword"))

    def test_is_connection_keyword(self):
        self.assertTrue(v.KeyWordValidator.is_connection_keyword("ssh"))

    def test_is_not_connection_keyword(self):
        self.assertFalse(v.KeyWordValidator.is_connection_keyword("asdfsd"))

    def test_set_integer_keyword(self):
        keywords = ["some_keyword"]
        self.assertFalse(v.KeyWordValidator.is_integer_keyword(keywords[0]))
        v.KeyWordValidator.set_extra_integer_keywords(keywords)
        self.assertTrue(v.KeyWordValidator.is_integer_keyword(keywords[0]))

    def test_is_integer_keyword(self):
        self.assertTrue(v.KeyWordValidator.is_integer_keyword("ansible_ssh_port"))

    def test_is_not_integer_keyword(self):
        self.assertFalse(v.KeyWordValidator.is_integer_keyword("some_keyword"))


class TestHostNameParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._backend_domain = "example.com"
        v.HostnameParser.set_backend_domain(cls._backend_domain)

    @classmethod
    def tearDownClass(cls):
        v.HostnameParser.set_backend_domain(None)

    def test_non_backend_domain_normalization(self):
        test_domain = "me.example.net"
        self.assertEqual(test_domain,
                         v.HostnameParser.normalize_hostname(test_domain))

    def test_backend_domain_normalization(self):
        prefix = "me"
        test_domain = "{0}.{1}.".format(prefix, self._backend_domain)
        self.assertEqual(prefix,
                         v.HostnameParser.normalize_hostname(test_domain))

    def test_nonrooted_backend_domain_normalization(self):
        prefix = "me"
        test_domain = "{0}.{1}".format(prefix, self._backend_domain)
        with self.assertRaises(MalformedInputException):
            v.HostnameParser.normalize_hostname(test_domain)


class TestGetIpaddr(unittest.TestCase):
    def test_get_good_ipaddr(self):
        ip_str = "1.2.3.4"
        ip_obj = ip_address(ip_str)
        self.assertEqual(ip_obj, v.get_ipaddr(ip_str))

    def test_get_bad_ipaddr(self):
        ip_str = "1.2.3.4adfdsf"
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_ipaddr(ip_str)


@mock.patch('inventory_tool.object.ippool.IPPool')
class TestGetIpPool(unittest.TestCase):
    def test_get_good_ippool(self, IPPoolMock):
        ip_str = "1.2.3.0/24"
        IPPoolMock.return_value = "test string"
        ret = v.get_ippool(ip_str)
        self.assertEqual(ret, IPPoolMock.return_value)
        IPPoolMock.assert_called_once_with(ip_str)

    def test_get_bad_ippool(self, IPPoolMock):
        ip_str = "1.2.3.4adfdsf"

        def raise_exception(*unused_l, **unused_kw):
            raise ValueError

        IPPoolMock.side_effect = raise_exception
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_ippool(ip_str)
        IPPoolMock.assert_called_once_with(ip_str)


@mock.patch('inventory_tool.validators.HostnameParser.normalize_hostname')
class TestGetFqdn(unittest.TestCase):
    def test_get_good_fqdn(self, HostnameParserMock):
        domain = 'www.example.com'
        HostnameParserMock.return_value = "test_string"
        ret = v.get_fqdn(domain)
        self.assertEqual(ret, HostnameParserMock.return_value)
        HostnameParserMock.assert_called_once_with(domain)

    def test_get_bad_fqdn(self, *unused):
        domain = 'www example.com'
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_fqdn(domain)

    def test_get_nonnormalizable_fqdn(self, HostnameParserMock):
        domain = 'www.example.com'

        def raise_exception(*unused_l, **unused_kw):
            raise MalformedInputException
        HostnameParserMock.side_effect = raise_exception
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_fqdn(domain)


class TestGetName(unittest.TestCase):
    def test_get_good_name(self):
        name_str = "some-name.some-extension"
        self.assertEqual(name_str, v.get_name(name_str))

    def test_get_bad_name(self):
        name_str = "this is a bad name"
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_name(name_str)


class TestGetKeyVal(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('inventory_tool.validators.KeyWordValidator')
        self.KeyWordValidatorMock = patcher.start()
        self.addCleanup(patcher.stop)
        self.KeyWordValidatorMock.is_integer_keyword.return_value = False
        self.KeyWordValidatorMock.is_ipnetwork_keyword.return_value = False
        self.KeyWordValidatorMock.is_ipaddress_keyword.return_value = False
        self.KeyWordValidatorMock.is_connection_keyword.return_value = False

    def test_non_keyval_arg(self):
        name_str = "this is:a bad keyval"
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_keyval(name_str)

    def test_plain_keyval(self):
        keyval = {"key": "integer_key", "val": "some_val"}
        ret = v.get_keyval("{0}:{1}".format(keyval["key"], keyval['val']))
        self.assertEqual(ret, keyval)
        self.KeyWordValidatorMock.is_integer_keyword.assert_called_once_with(keyval['key'])

    def test_good_integer_keyval(self):
        self.KeyWordValidatorMock.is_integer_keyword.return_value = True
        keyval = {"key": "integer_key", "val": 1234}
        ret = v.get_keyval("{0}:{1}".format(keyval["key"], keyval['val']))
        self.assertEqual(ret, keyval)
        self.KeyWordValidatorMock.is_integer_keyword.assert_called_once_with(keyval['key'])

    def test_bad_integer_keyval(self):
        self.KeyWordValidatorMock.is_integer_keyword.return_value = True
        keyval = {"key": "integer_key", "val": 'not_an_int'}
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_keyval("{0}:{1}".format(keyval["key"], keyval['val']))

    @mock.patch('inventory_tool.validators.get_ipaddr')
    def test_good_ipaddress_keyval(self, GetIpMock):
        key = "ipaddress_key"
        val = "1.2.3.4"
        self.KeyWordValidatorMock.is_ipaddress_keyword.return_value = True
        GetIpMock.return_value = ip_address(val)
        ret = v.get_keyval("{0}:{1}".format(key, val))
        self.assertEqual(ret, {"key": key, "val": GetIpMock.return_value})
        self.KeyWordValidatorMock.is_ipaddress_keyword.assert_called_once_with(key)

    @mock.patch('inventory_tool.validators.get_ipaddr')
    def test_bad_ipaddress_keyval(self, GetIpMock):
        self.KeyWordValidatorMock.is_ipaddress_keyword.return_value = True

        def raise_exception(*unused_l, **unused_kw):
            raise argparse.ArgumentTypeError

        GetIpMock.side_effect = raise_exception
        keyval = {"key": "ipaddress_key", "val": 'not_an_ip'}
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_keyval("{0}:{1}".format(keyval["key"], keyval['val']))

    @mock.patch('inventory_tool.validators.get_ipaddr')
    def test_autoassigned_ipaddress_keyval(self, GetIpMock):
        key = "ipaddress_key"
        self.KeyWordValidatorMock.is_ipaddress_keyword.return_value = True
        ret = v.get_keyval(key)
        self.assertEqual(ret, {"key": key, "val": None})
        self.KeyWordValidatorMock.is_ipaddress_keyword.assert_called_once_with(key)

    def test_good_ipnetwork_keyval(self):
        self.KeyWordValidatorMock.is_ipnetwork_keyword.return_value = True
        key = "ipnetwork_key"
        val = "1.2.3.0/24"
        ret = v.get_keyval("{0}:{1}".format(key, val))
        self.assertEqual(ret, {"key": key, "val": ip_network(val)})
        self.KeyWordValidatorMock.is_ipnetwork_keyword.assert_called_once_with(key)

    def test_bad_ipnetwork_keyval(self):
        self.KeyWordValidatorMock.is_ipnetwork_keyword.return_value = True
        key = "ipnetwork_key"
        val = "not-a-network"
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_keyval("{0}:{1}".format(key, val))

    def test_good_connection_keyval(self):
        self.KeyWordValidatorMock.is_connection_keyword.return_value = True
        key = "ansible_connection"
        val = "ssh"
        ret = v.get_keyval("{0}:{1}".format(key, val))
        self.assertEqual(ret, {"key": key, "val": val})
        self.KeyWordValidatorMock.is_connection_keyword.assert_called_once_with(val)

    def test_bad_connection_keyval(self):
        self.KeyWordValidatorMock.is_connection_keyword.return_value = False
        key = "ansible_connection"
        val = "not-ssh"
        with self.assertRaises(argparse.ArgumentTypeError):
            v.get_keyval("{0}:{1}".format(key, val))
        self.KeyWordValidatorMock.is_connection_keyword.assert_called_once_with(val)
