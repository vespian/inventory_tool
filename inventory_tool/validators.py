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

import argparse
import re

from inventory_tool.exception import MalformedInputException
from inventory_tool.object.ippool import IPPool

# For Python3 < 3.3, ipaddress module is available as an extra module,
# under a different name:
try:
    from ipaddress import ip_address
    from ipaddress import ip_network
except ImportError:
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPNetwork as ip_network


class KeyWordValidator():
    _default_ipaddres_keywords = ["ansible_ssh_host", ]
    _ipaddres_keywords = _default_ipaddres_keywords

    _default_ipnetwork_keywords = []
    _ipnetwork_keywords = _default_ipnetwork_keywords

    # These do not change that often:
    _connection_keywords = ["local", "ssh", "paramiko", "smart", ]

    _default_integer_keywords = ["ansible_ssh_port", ]
    _integer_keywords = _default_integer_keywords

    @classmethod
    def set_extra_ipaddress_keywords(cls, keywords):
        cls._ipaddres_keywords = cls._default_ipaddres_keywords + keywords

    @classmethod
    def is_ipaddress_keyword(cls, keyword):
        return keyword in cls._ipaddres_keywords

    @classmethod
    def get_ipaddress_keywords(cls):
        return list(cls._ipaddres_keywords)

    @classmethod
    def set_extra_ipnetwork_keywords(cls, keywords):
        cls._ipnetwork_keywords = cls._default_ipnetwork_keywords + keywords

    @classmethod
    def is_ipnetwork_keyword(cls, keyword):
        return keyword in cls._ipnetwork_keywords

    @classmethod
    def get_ipnetwork_keywords(cls):
        return list(cls._ipnetwork_keywords)

    @classmethod
    def is_connection_keyword(cls, keyword):
        return keyword in cls._connection_keywords

    @classmethod
    def get_connection_keywords(cls):
        return list(cls._connection_keywords)

    @classmethod
    def set_extra_integer_keywords(cls, keywords):
        cls._integer_keywords = cls._default_integer_keywords + keywords

    @classmethod
    def is_integer_keyword(cls, keyword):
        return keyword in cls._integer_keywords


class HostnameParser():
    @classmethod
    def normalize_hostname(cls, name):
        """Remove backend domain from hostname

        Args:
            name: hostname to standarize

        Returns:
            Hostname relative to cls._backend_domain. Function returns
            unchanged string if hostname was absolute (but in different
            domain), or already relative.
        """
        if cls._backend_domain in name and name[-1] != '.':
            msg = "{0} contains default backend domain, append '.' to the end " + \
                  "to force absolute dns names"
            raise MalformedInputException(msg.format(name))
        suffix = '.' + cls._backend_domain + '.'
        if re.search(suffix + '$', name):
            return name[:-len(suffix)]
        else:
            return name

    @classmethod
    def set_backend_domain(cls, domain):
        cls._backend_domain = domain


def get_ippool(string):
    """Parse network string into IPPool object

    Parses an IPv4/6 network string and creates an IPPool object basing on it.

    Args:
        string: string to parse

    Returns:
        An empty IPPool object (i.e. without any allocated/reserved IP)

    Raises:
        argparse.ArgumentTypeError: string does not represent a valid ipv4/6
        network.
    """
    try:
        tmp = IPPool(string)
    except ValueError as e:
        msg = "IPPool network requires proper " + \
              "ipv4/ipv6 network as a value: " + str(e)
        raise argparse.ArgumentTypeError(msg)
    return tmp


def get_ipaddr(string):
    """Parse ip address string into ipaddress.ip_address object

    Parses an IPv4/6 address string and creates an ipaddress.ip_address object
    basing on it.

    Args:
        string: string to parse

    Returns:
        An ipaddress.ip_address object.

    Raises:
        argparse.ArgumentTypeError: string does not represent a valid ipv4/6
        address.
    """
    try:
        tmp = ip_address(string)
    except ValueError as e:
        msg = "A valid ipv4/ipv6 addreess is required: " + str(e)
        raise argparse.ArgumentTypeError(msg)
    return tmp


def get_fqdn(string):
    """Check whether string is valid domain name.

    If string is not a valid domain name, then exceptions are raised, otherwise
    string is returned unchanged.

    Args:
        string: string to parse

    Returns:
        String passed via "string" parameter.

    Raises:
        argparse.ArgumentTypeError: string does not represent a valid domain
        name or is a relative name and contains backend_domain string.
    """
    match = re.match(r'(([a-z0-9]\-*[a-z0-9]*){1,63}\.?){1,255}$', string)
    if not match:
        msg = "{0} is not proper domain name.".format(string)
        raise argparse.ArgumentTypeError(msg)
    try:
        return HostnameParser.normalize_hostname(string)
    except MalformedInputException as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def get_name(string):
    """Checks if string is a valid name (group/host/ippool/etc...)

    If string is an invalid name, then exceptions are raised, otherwise
    string is returned unchanged.

    Args:
        string: string to parse

    Returns:
        String passed via "string" parameter.

    Raises:
        argparse.ArgumentTypeError: string does not represent a valid
        name.
    """
    match = re.match(r'[\w\-\.]{2,}$', string)
    if not match:
        msg = "{0} is not proper name.".format(string)
        raise argparse.ArgumentTypeError(msg)
    return string


def get_keyval(string):
    """Parse a key-value string into object.

    Function validates key-value string depending on the key and
    retrns parsed objects.

    Args:
        string: a string in "key:val" format or just "key" in case of auto-
            generated variables.

    Returns:
        A hash with key "key" being the parsed key and the key "val" being
        the parsed value or None in case of auto-generated vars.

    Raises:
        argparse.ArgumentTypeError: Key and/or val are malformed or the parsed
        val does not conform to key requirements.
    """
    match = re.match(r'([\w\-]{2,})(?::([\w\-\./\\\@]{2,}))?$', string)
    if not match:
        msg = "{0} is not proper key-val argument.".format(string)
        raise argparse.ArgumentTypeError(msg)
    ret = {"key": match.group(1), "val": match.group(2)}

    # Integer type k-vals:
    if KeyWordValidator.is_integer_keyword(ret["key"]):
        try:
            ret["val"] = int(ret["val"])
            return ret
        except ValueError:
            msg = "Key param {0}".format(ret["key"])
            msg += " requires integer as a value."
            raise argparse.ArgumentTypeError(msg)

    # ipaddress type k-vals:
    if KeyWordValidator.is_ipaddress_keyword(ret["key"]):
        # Will be auto-assigned later on:
        if ret["val"] is None:
            return ret
        ret["val"] = get_ipaddr(ret["val"])
        return ret

    # ipnetwork type k-vals:
    if KeyWordValidator.is_ipnetwork_keyword(ret["key"]):
        try:
            ret["val"] = ip_network(ret["val"])
            return ret
        except ValueError as e:
            msg = "Key param {0} requires proper ".format(ret["key"]) + \
                  "ipv4/ipv6 network as a value: " + str(e)
            raise argparse.ArgumentTypeError(msg)

    # ansible_connection type k-val:
    if ret["key"] == "ansible_connection":
        if not KeyWordValidator.is_connection_keyword(ret["val"]):
            msg = "Key param {0} requires ".format(ret["key"]) + \
                  "one of following connection types: " + \
                  ','.join(KeyWordValidator.get_connection_keywords()) + \
                  " as a value."
            raise argparse.ArgumentTypeError(msg)
        else:
            return ret

    # ansible_ssh_user and others:
    return ret
