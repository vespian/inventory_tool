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
import hashlib
import logging
import logging.handlers
import re
import sys
import yaml

# For Python3 < 3.3, ipaddress module is available as an extra module,
# under a different name:
try:
    from ipaddress import ip_address
    from ipaddress import ip_network
    from ipaddress import IPv4Address
    from ipaddress import IPv6Address
    ipaddress_name_network = "network_address"
    ipaddress_name_broadcast = "broadcast_address"
except ImportError:
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPNetwork as ip_network
    from ipaddr import IPv4Address
    from ipaddr import IPv6Address
    ipaddress_name_network = "network"
    ipaddress_name_broadcast = "broadcast"

# Simplejason is updated more frequently, lets check if it is installed:
try:
    import simplejson as json
except ImportError:
    import json

# Try LibYAML first and if unavailable, fall back to pure Python implementation
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    # Logger will not be initialized yet :/
    print("WARNING! libyaml is unavailable, loading slower - pure-python " +
          "implementation of yaml bindings.", file=sys.stderr)
    from yaml import Loader, Dumper

# Constants:
MIN_SUPPORTED_INVENTORY_FORMAT = 1
__version__ = '1.0'


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
        return Host.normalize_hostname(string)
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
            msg = "Key param {0} requires integer as a value.".format(ret["key"])
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
        if not KeyWordValidator.is_connection_keyword(ret["key"]):
            msg = "Key param {0} requires ".format(ret["key"]) + \
                  "one of following connection types: " + \
                  ','.join(KeyWordValidator.get_connection_keywords()) + " as a value."
            raise argparse.ArgumentTypeError(msg)
        else:
            return ret

    # ansible_ssh_user and others:
    return ret


def parse_commandline(script_path, commandline):
    """Parse command line into script configuration

    Parses commandline into a Namespace, provides -h/--help options, and
    enforces some syntax checking on input parameters.

    Args:
        script_path: path to the script that calls this function
        commandline: a list of command line parameters

    Returns:
        A Namespace object that contains variables set according to the
        command line parameters passed in "commandline" param.
    """
    parser = argparse.ArgumentParser(
        description='Dynamic inventory script for {0}.'.format(script_path),
        epilog="Author: Pawel Rozlach <pawel.rozlach@brainly.com>",
        add_help=True,
        prog=script_path)
    parser.add_argument(
        '--version',
        action='version',
        version=__version__)
    parser.add_argument(
        "-v", "--verbose",
        action='store_true',
        help="Provide extra logging messages.")
    parser.add_argument(
        "--initialize-inventory",
        action='store_true',
        help="Start with empty inventory.")
    parser.add_argument(
        "-s", "--std-err",
        action='store_true',
        help="Log to stderr instead of /dev/null")

    # Ansible related stuff
    parser.add_argument(
        "--list",
        action='store_true',
        default=False,
        help="Dump all inventory data in JSON (used by Ansible itself).")

    # HACK, HACK, HACK!
    # This fragment makes my eyes bleed, but unfortunatelly, argparse has
    # messed things up badly:
    #   http://bugs.python.org/issue9253
    #   http://bugs.python.org/issue16308
    # So basically, it works in 3.3, it does not work in 3.2(==Wheezy) :/
    major, minor, _, _, _ = sys.version_info
    if major == 3 and minor < 3:
        if ("--list" in commandline or "--initialize-inventory" in commandline) and \
                "-h" not in commandline and "--help" not in commandline:
            args = parser.parse_args(commandline)
            if args.list or args.initialize_inventory:
                # Return as-is, parsers are not needed in this case anyway
                return args

    subparsers = parser.add_subparsers(help='subcommand groups',
                                       dest='subcommand')

    # IP Pool related
    parser_ippool = subparsers.add_parser("ippool",
                                          help="IP address pools manipulation.")
    parser_ippool.add_argument(
        "-n", "--ippool-name",
        action='store',
        type=get_name,
        help="Name of the IP pool.")
    mutexgroup_ippool = parser_ippool.add_mutually_exclusive_group(required=True)
    mutexgroup_ippool.add_argument(
        "-a", "--add",
        action="store",
        type=get_ippool,
        metavar="network",
        help="Add a new ippool.",)
    mutexgroup_ippool.add_argument(
        "-d", "--delete",
        action="store_true",
        default=False,
        help="Delete an ippool",)
    mutexgroup_ippool.add_argument(
        "-i", "--assign",
        action="store",
        nargs=2,
        type=get_name,
        metavar=("group-name", "retlated-var-name"),
        help="Assign the ippool to a group",)
    mutexgroup_ippool.add_argument(
        "-r", "--revoke",
        action="store",
        nargs=2,
        type=get_name,
        metavar=("group-name", "retlated-var-name"),
        help="Revoke the ippool from a group",)
    mutexgroup_ippool.add_argument(
        "-b", "--book",
        action="store",
        type=get_ipaddr,
        metavar="ip-address",
        help="Reserve an ip addres for future use.",)
    mutexgroup_ippool.add_argument(
        "-c", "--cancel",
        action="store",
        type=get_ipaddr,
        metavar="ip-address",
        help="Restore to the pool an ip address reserved by -b/--book option.")
    mutexgroup_ippool.add_argument(
        "-s", "--show",
        action="store_true",
        default=False,
        help="Detailed information about IP pool.",)
    mutexgroup_ippool.add_argument(
        "-l", "--list-all",
        action="store_true",
        default=False,
        help="List available IP pools.",)

    # Group related
    parser_group = subparsers.add_parser("group",
                                         help="Group membership manipulation.")
    parser_group.add_argument(
        "-n", "--group-name",
        action='store',
        type=get_name,
        help="Name of the group to work with.")
    mutexgroup_group = parser_group.add_mutually_exclusive_group(required=True)
    mutexgroup_group.add_argument(
        "-l", "--list-all",
        action='store_true',
        default=False,
        help="List all available groups.")
    mutexgroup_group.add_argument(
        "-a", "--add",
        action="store_true",
        default=False,
        help="Add a new group.",)
    mutexgroup_group.add_argument(
        "-d", "--delete",
        action="store_true",
        default=False,
        help="Delete a group",)
    mutexgroup_group.add_argument(
        "-s", "--show",
        action="store_true",
        default=False,
        help="Show group's children and member hosts.",)
    mutexgroup_group.add_argument(
        "--child-add",
        action="store",
        type=get_name,
        metavar="child-name",
        help="Add a child group to the group",)
    mutexgroup_group.add_argument(
        "--child-del",
        action="store",
        type=get_name,
        metavar="child-name",
        help="Delete a child group from the group",)
    mutexgroup_group.add_argument(
        "--host-add",
        action="store",
        type=get_name,
        metavar="host-name",
        help="Add a host to the group",)
    mutexgroup_group.add_argument(
        "--host-del",
        action="store",
        type=get_name,
        metavar="host-name",
        help="Delete a host from the group",)

    # Host related
    parser_host = subparsers.add_parser("host",
                                        help="Host manipulation.")
    parser_host.add_argument(
        "-n", "--host-name",
        action='store',
        type=get_fqdn,
        help="Name of the host to work with.")
    mutexgroup_host = parser_host.add_mutually_exclusive_group(required=True)
    mutexgroup_host.add_argument(
        "-l", "--list-all",
        action="store_true",
        default=False,
        help="List all hosts.",)
    mutexgroup_host.add_argument(
        "-a", "--add",
        action="store_true",
        default=False,
        help="Add a new host.",)
    mutexgroup_host.add_argument(
        "-d", "--delete",
        action="store_true",
        default=False,
        help="Delete a host",)
    mutexgroup_host.add_argument(
        "-s", "--show",
        action="store_true",
        default=False,
        help="Show hosts data.",)
    mutexgroup_host.add_argument(
        "--var-set",
        action="store",
        type=get_keyval,
        nargs="+",
        metavar="key:val",
        help="Add a key:val pair to host. Depending on the key, val may be " +
             "optional")
    mutexgroup_host.add_argument(
        "--var-del",
        action="store",
        type=get_name,
        nargs="+",
        metavar="key",
        help="Delete a key:val pairs from the host data.",)
    mutexgroup_host.add_argument(
        "--alias-add",
        action="store",
        type=get_fqdn,
        metavar="alias",
        help="Add an alias name to the host.",)
    mutexgroup_host.add_argument(
        "--alias-del",
        action="store",
        type=get_fqdn,
        metavar="alias",
        help="Remove an alias from the host.",)

    args = parser.parse_args(commandline)

    # Quick fix for things imposible with argparse:
    if (not (args.list or args.initialize_inventory)) and args.subcommand is None:
        print("Nothing to do, please define one of subcommands or use" +
              "-i/--initialize-inventory/--list switch.", file=sys.stderr)
        sys.exit(1)
    if args.list and args.subcommand is not None:
        print("Subcommands and --list switch are mutually exclusive.",
              file=sys.stderr)
        sys.exit(1)
    if args.subcommand in ["ippool", "group", "host"]:
        name = args.__getattribute__("{0}_name".format(
                                     args.subcommand.replace("-", "_")))
        if args.list_all:
            if name is not None:
                print("--list-all/-l and -n/--{0}-name".format(args.subcommand) +
                      " options are mutually exclusive", file=sys.stderr)
                sys.exit(1)
        else:
            if name is None:
                print("-n/--{0}-name".format(args.subcommand) +
                      " option has not been specified", file=sys.stderr)
                sys.exit(1)

    return args


class ScriptException(Exception):
    """A base class for exceptions defined locally/in this script"""
    pass


class MalformedInputException(ScriptException):
    """Bad user input exception

    An exception raised when user provides bad/malformed input
    """
    pass


class BadDataException(ScriptException):
    """Data loaded/parsed/generated by the script is invalid"""
    pass


class GenericException(ScriptException):
    """Error condidation not covered by other exceptions"""
    pass


class IPPool:
    """IP pool representation and manipulation

    This class takes care of managing ip pools available, and this includes:
    - assigning and releasing IPs, both manually and automatically
    - booking and canceling IPs for special use
    - serialization of IP pools for storage in YAML documents
    - human readable representation of ip pools
    """

    __slots__ = ['_network', '_allocated', '_reserved']

    def __init__(self, network, allocated=[], reserved=[]):
        """Init IPPool

        Args:
            network: network from which ip addresses should be allocated
            allocated: list of ip addres strings that are already allocated
            reserved: list of ip address strings that should not be available
                for allocation.

        Raises:
            ValueError: ip address or network is invalid or malformed.
        """
        self._network = ip_network(network)
        self._allocated = [ip_address(x) for x in allocated]
        self._reserved = [ip_address(x) for x in reserved]

    def get_hash(self):
        """Extract data from object in a way suitable for serializing

        Returns:
            Method returns data necessary for re-initializing the same object in
            a form suitable for serialization using YAML/JSON. Normally, this
            object contains other objects which can not be easily serialized or
            are not very readable after serializing.
        """
        tmp = {"network": str(self._network),
               "allocated": sorted([str(x) for x in self._allocated]),
               "reserved": sorted([str(x) for x in self._reserved]),
               }
        return tmp

    def allocate(self, ip=None):
        """Allocate an IP from the pool.

        Method allocates next free adress from the pool if ip is None, or
        marks given ip as already allocated

        Args:
            ip: either None or ipaddress.ip_address object

        Returns:
            An ip that has been allocated. In case when "ip" argument is not
            none, then the object pointed by it is returned.

        Raises:
            MalformedInputException - user provided data is invalid
            GenericException - pool has run out of free ip adresses
        """
        if ip is not None:
            if ip not in self._network:
                msg = "Attempt to allocate IP from outside of the pool: "
                msg += "{0} is not in {1}.".format(ip, self._network)
                raise MalformedInputException(msg)
            if ip in self._allocated:
                msg = "Attempt to allocate already allocated IP: " + str(ip)
                raise MalformedInputException(msg)
            elif ip in self._reserved:
                msg = "Attempt to allocate from reserved pool: " + str(ip)
                raise MalformedInputException(msg)
            else:
                self._allocated.append(ip)
                return ip
        else:
            for candidate in [x for x in self._network
                              if x != self._network.__getattribute__(ipaddress_name_broadcast) and
                              x != self._network.__getattribute__(ipaddress_name_network)]:
                if candidate not in self._allocated and \
                        candidate not in self._reserved:
                    logging.info(
                        "IP {0} has been auto-assigned.".format(candidate))
                    self._allocated.append(candidate)
                    return candidate
            msg = "The pool has run out of free ip addresses."
            raise GenericException(msg)

    def release(self, ip):
        """Mark given IP as free, available for allocation.

        Args:
            ip: ip to deallocate

        Raises:
            MalformedInputException: provided ip has not been alocated yet.
        """
        if ip in self._allocated:
            self._allocated.remove(ip_address(ip))
        else:
            msg = "An attempt to release a inexistant ip {0} ".format(ip)
            msg += "from allocated ips list."
            raise MalformedInputException(msg)

    def release_all(self):
        """Mark all ip addresses in the pool as available"""
        self._allocated = []

    def overlaps(self, other):
        """Check if IP pools overlap

        Args:
            other: ip pool to check for overlap with this pool
        """
        return self._network.overlaps(other._network)

    def book(self, ip):
        """Prevent IP from being allocated.

        Marks given IP as reserved/unavailable for allocation.

        Args:
            ip: ip to book.

        Raises:
            MalformedInputException: ip does not belong to this pool
        """
        if ip not in self._network:
            msg = "IP {0} does not belong to network {1}".format(ip, self._network)
            raise MalformedInputException(msg)
        else:
            self._reserved.append(ip)

    def cancel(self, ip):
        """Remove reservation of an IP address

        Marks given IP as available for allocation.

        Args:
            ip: ip to release

        Raises:
            MalformedInputException: ip has not been reserved yet.
        """
        if ip in self._reserved:
            self._reserved.remove(ip)
        else:
            msg = "IP {0} has not been reserved yet".format(ip)
            raise MalformedInputException(msg)

    def __contains__(self, other):
        """Check if ip belongs to the pool.

        Args:
            other: ip, either as a string or an ipaddress.ip_address object
                to check the membership for.
        """
        if isinstance(other, str):
            tmp = ip_address(other)
            return tmp in self._network
        elif isinstance(other, IPv4Address) or \
                isinstance(other, IPv6Address):
            return other in self._network

    def __str__(self):
        """Present object in human-readable form"""
        msg = "Network: {0}\n".format(self._network)
        msg += "Allocated:\n"
        if self._allocated:
            for tmp in self._allocated:
                msg += "\t- {0}\n".format(tmp)
        else:
            msg += "\t<None>\n"
        msg += "Reserved:\n"
        if self._reserved:
            for tmp in self._reserved:
                msg += "\t- {0}\n".format(tmp)
        else:
            msg += "\t<None>\n"


class Host:
    """Host manipulation and representation.

    This class takes care of managing host, and this includes:
    - assigning and removing aliases
    - assigning and removing keyval arguments
    - serialization of host objects for storage in YAML documents
    - human readable representation of hosts
    """

    __slots__ = ['_aliases', '_keyvals', ]

    def __init__(self, aliases=[], keyvals={}):
        """Build a new Host object

        Args:
            aliases: a list of aliases that should be assigned to this host
            keyvals: a hash containing all the key:value pairs.

        Raises:
            BadDataException: ip address or network is invalid or malformed.
        """
        self._aliases = list(aliases)
        self._keyvals = {}
        for key in keyvals:
            try:
                if KeyWordValidator.is_ipaddress_keyword(key):
                    self._keyvals[key] = ip_address(keyvals[key])
                elif KeyWordValidator.is_ipnetwork_keyword(key):
                    self._keyvals[key] = ip_network(keyvals[key])
                else:
                    self._keyvals[key] = keyvals[key]
            except ValueError:
                msg = "Data for key {0} is not a valid ip network/address,"
                msg += " failed to initialize Host object"
                raise BadDataException(msg.format(key))

    def __str__(self):
        """Present object in human-readable form"""
        ret = "Aliases:\n"
        if self._aliases:
            for alias in self._aliases:
                ret += "\t- {0}\n".format(alias)
        else:
            ret += "\t<None>\n"
        ret += "Host variables:\n"
        if self._keyvals:
            for keyval in self._keyvals:
                ret += "\t{0}:{1}\n".format(keyval, self._keyvals[keyval])
        else:
            ret += "\t<None>\n"
        return ret

    def get_hash(self):
        """Extract data from object in a way suitable for serializing

        Returns:
            Method returns data necessary for re-initializing the same object in
            a form suitable for serialization using YAML/JSON. Normally, this
            object contains other objects which can not be easily serialized or
            are not very readable after serializing.
        """
        tmp = {"aliases": sorted(self._aliases),
               "keyvals": {x: str(self._keyvals[x]) for x in self._keyvals},
               }
        return tmp

    def get_keyval(self, key=None, reporting=True):
        """Get a value for given key or all keyvals

        Important to note is the fact that exception handling is quite heavy,
        so for loops that issue a lot of obj.get_keyval calls, we specify
        reporting=False param and just check for None object as an output.

        Args:
            key: key of the value that should be returned. None if returning
                all keys is desired.
            reporting: In case of inexistant key, should an exception be
                returned or just a 'None'.

        Raises:
            MalformedInputException: only when reporting is True - provided key
                has not been found in hosts data
        """
        if key is None:
            ret = self._keyvals.copy()
            ret['aliases'] = list(self._aliases)
            return ret
        elif key == 'aliases':
            return list(self._aliases)
        else:
            if key in self._keyvals:
                return self._keyvals[key]
            elif reporting:
                raise MalformedInputException(
                    "Key {0} has not been found.".format(key))
            else:
                return None

    def set_keyval(self, keyval):
        """Set key to val in hosts data

        Args:
            keyval: a hash with two keys:
                {"key": key of the variable, "val": variable's value}
        """
        self._keyvals[keyval["key"]] = keyval["val"]

    def del_keyval(self, key):
        """Remove val identified by key

        Args:
            key: key to remove

        Raises:
            MalformedInputException: key has not been set yet.
        """
        if key in self._keyvals:
            del self._keyvals[key]
        else:
            raise MalformedInputException("Key {0} has not been found.".format(key))

    def alias_add(self, alias):
        """Add new alias for the host

        Args:
            alias: alias to add

        Raises:
            MalformedInputException: alias is already present in the aliases list
        """
        alias_n = self.normalize_hostname(alias)
        if alias_n not in self._aliases:
            self._aliases.append(alias_n)
        else:
            msg = "Alias {0} has already been added."
            raise MalformedInputException(msg.format(alias_n))

    def alias_del(self, alias):
        """Remove alias

        Args:
            alias: alias to remove

        Raises:
            MalformedInputException: alias has not been set yet
        """
        alias_n = self.normalize_hostname(alias)
        if alias_n in self._aliases:
            self._aliases.remove(alias_n)
        else:
            raise MalformedInputException("Alias {0} has not been ".format(alias_n) +
                                          "assigned to this host yet.")

    def get_aliases(self, alias=None, reporting=True):
        """Get or check the list of aliases currently assigned to host

        Args:
            alias: alias to check for presence, or None if all aliases should
                be returned.
            reporting: In case of inexistant alias, should an exception be
                returned or just a 'None'.

        Returns:
            None if alias does not exist, or all aliases in case when alias==None
            or the alias itself if alias has already been defined/added.
        """
        if alias is None:
            return list(self._aliases)
        else:
            if alias in self._aliases:
                return alias
            elif reporting:
                raise MalformedInputException(
                    "Alias {0} has not been found.".format(alias))
            else:
                return None

    @classmethod
    def normalize_hostname(cls, name):
        """Remove backend domain from hostname

        Args:
            name: hostname to standarize

        Returns:
            Hostname relative to cls._backend_domain. Function returns unchanged
            string if hostname was absolute (but in different domain), or
            already relative.
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


class Group:
    """Group manipulation and representation.

    This class takes care of managing group, and this includes:
    - managing hosts and child groups
    - assignement of ippools
    - serialization of host objects for storage in YAML documents
    - human readable representation of hosts
    """

    __slots__ = ['_hosts', '_children', '_ippools', ]

    def __init__(self, hosts=[], children=[], ippools={}):
        """Build a new Group object

        Args:
            hosts: a list of hosts that belong to this group
            children: a list of child group blonging to this group
            ippools: assignement of ippools to host variables. This has a form
                of a hash: {"<variable-name>": "<ippool-name>"}
        """
        self._hosts = list(hosts)
        self._children = list(children)
        self._ippools = ippools.copy()

    def __str__(self):
        """Present object in human-readable form"""
        ret = "Hosts:\n"
        if self._hosts:
            for host in self._hosts:
                ret += "\t- {0}\n".format(host)
        else:
            ret += "\t<None>\n"
        ret += "Children:\n"
        if self._children:
            for child in self._children:
                ret += "\t- {0}\n".format(child)
        else:
            ret += "\t<None>\n"
        ret += "Ip pools:\n"
        if self._ippools:
            for var in self._ippools:
                ret += "\t{0}:{1}\n".format(var, self._ippools[var])
        else:
            ret += "\t<None>\n"
        return ret

    def get_hash(self):
        """Extract data from object in a way suitable for serializing

        Returns:
            Method returns data necessary for re-initializing the same object in
            a form suitable for serialization using YAML/JSON. Normally, this
            object contains other objects which can not be easily serialized or
            are not very readable after serializing.
        """
        tmp = {"hosts": sorted(self._hosts),
               "children": sorted(self._children),
               "ippools": self._ippools.copy(),
               }
        return tmp

    def has_child(self, child):
        """Check if a group is a subgroup of this group

        Args:
            child: group which membership we are checking
        """
        return child in self._children

    def get_children(self):
        """Get all subgroups(children) names this group has"""
        return list(self._children)  # Shallow copy

    def add_child(self, child):
        """Add a child group to the group

        Args:
            child: child group we are adding

        Raises:
            MalformedInputException: child has already been aded
        """
        if child not in self._children:
            self._children.append(child)
        else:
            msg = "Child {0} has already been added to this group"
            raise MalformedInputException(msg.format(child))

    def del_child(self, child, reporting=True):
        """Remove a child group  from this group

        Important to note is the fact that exception handling is quite heavy,
        so for loops that issue a lot of obj.del_child calls, we specify
        reporting=False param and just return nothing.

        Args:
            child: the name of the child group to remove
            reporting: In case of inexistant key, should an exception be
                returned or just a 'None'.

        Raises:
            MalformedInputException: only when reporting is True - child group
                specified by "child" parameter has not been assigned to this
                group yet.
        """
        if child in self._children:
            self._children.remove(child)
        elif reporting:
            raise MalformedInputException("Child group {0} could".format(child) +
                                          " not be found in this group.")

    def has_host(self, host):
        """Check if host belongs to this group"""
        host_n = Host.normalize_hostname(host)
        return host_n in self._hosts

    def get_hosts(self):
        """Return all the hosts that belong to this group"""
        return list(self._hosts)  # Shallow copy

    def add_host(self, host):
        """Add host to group

        Args:
            host: host to add

        Raises:
            MalformedInputException: host has already been added to the group,
                or host name is malformed.
        """
        host_n = Host.normalize_hostname(host)
        if host_n not in self._hosts:
            self._hosts.append(host_n)
        else:
            msg = "Host {0} has already been added to this group"
            raise MalformedInputException(msg.format(host_n))

    def del_host(self, host, reporting=True):
        """Delete host from the group

        Important to note is the fact that exception handling is quite heavy,
        so for loops that issue a lot of obj.del_host calls, we specify
        reporting=False param and return nothing.

        Args:
            host: host to remove

        Raises:
            MalformedInputException: only when reporting is True - child group
                specified by "child" parameter has not been assigned to this
                group yet, or the hostname is malformed.
        """
        host_n = Host.normalize_hostname(host)
        if host_n in self._hosts:
            self._hosts.remove(host_n)
        elif reporting:
            raise MalformedInputException("Host {0} could".format(host_n) +
                                          " not be found in this group.")

    def get_pool(self, var):
        """Fetch IPPool's name assigned to the group.

        Check which ip pool is assigned to given variable.

        Args:
            var: a variable that uses ippool to fetch

        Returns:
            Name of the IPPool if variable is defined for given group, None
            otherwise.
        """
        if var in self._ippools:
            return self._ippools[var]
        else:
            return None

    def set_pool(self, var, name):
        """Assign a pool name to a variable.

        Links IPPool with some hostvar, thus allowing for auto-assigning of
        ipaddresses for this hostvar.

        Args:
            var: variable to assign pool to
            name: name of the ippool to assign it to.
        """
        self._ippools[var] = name

    def del_pool_by_var(self, var):
        """Unlink ip pool from variable

        Removes the link between some hostvar and an IPPool for given group.

        Args:
            var: variable from which ippool should be unlinked
        """
        try:
            del self._ippools[var]
        except KeyError:
            logging.debug("Ignoring removal of already absent pool for var " +
                          var)

    # Awkward ;)
    def del_pool_by_pool(self, pool):
        """Unlink a pool from variable.

        Removes the link between some hostvar and an IPPool for given group.

        Args:
            pool: pool that should be unlinked.
        """
        for item in self._ippools.items():
            if item[1] == pool:
                logging.debug("Removing pool by pool {0}:{1}.".format(
                    item[0], item[1]))
                del self._ippools[item[0]]


class InventoryData:
    """Representation of the inventory and it's dependencies.

    This class takes care of managing inventory, and this includes:
    - host<->group<->ipppols relations
    - serialization and persistance of inventory data in human readable form
    - hostvars handling
    - ip address auto-assign handling
    """

    __slots__ = ['_inventory_path', '_data', '_is_recalculated']

    def __init__(self, inventory_path, initialize=False):
        """Build a new InventoryData object

        Args:
            inventory_path: a patch where the inventory is stored
            initialize: defines whether an empty directory object should be
                created or already existing one loaded.

        Raises:
            BadDataException: stored inventory is malformed and cannot be read.
            MalformedInputException: stored inventory has some incoherent data
        """
        self._inventory_path = inventory_path
        self._is_recalculated = False
        if initialize:
            self._data = {"hosts": {},
                          "groups": {},
                          "ippools": {},
                          "_meta": {"version": MIN_SUPPORTED_INVENTORY_FORMAT,
                                    "checksum": ""},
                          }
            return
        else:
            with open(self._inventory_path, 'rb') as fh:
                tmp = fh.read()
            self._data = yaml.load(tmp, Loader=Loader)
            # Check if will be able to work with this data:
            if self._data["_meta"]["version"] < MIN_SUPPORTED_INVENTORY_FORMAT:
                msg = "Inventory format: {0}, min supported format: {1}".format(
                      self._data["_meta"]["version"],
                      MIN_SUPPORTED_INVENTORY_FORMAT)
                logging.debug(msg)
                raise BadDataException("Inventory data is in unsuported/old " +
                                       "format, please update your tools")
            # Calculate checksum before parsing data into objects:
            checksum_hash = self._data.copy()  # Shallow copy
            del checksum_hash["_meta"]
            tmp = yaml.dump(checksum_hash, Dumper=Dumper, encoding='utf-8',
                            default_flow_style=False)
            checksum = hashlib.sha256(tmp).hexdigest()
            # Parse IPPools into objects:
            logging.debug("Parsing ippools into objects")
            for ippool in self._data["ippools"]:
                tmp = self._data["ippools"][ippool]
                obj = IPPool(network=tmp["network"],
                             allocated=tmp["allocated"],
                             reserved=tmp["reserved"],)
                self._data["ippools"][ippool] = obj
            # Parse Hosts into objects:
            logging.debug("Parsing hosts into objects")
            for host in self._data["hosts"]:
                self._data["hosts"][host] = Host(
                    aliases=self._data["hosts"][host]['aliases'],
                    keyvals=self._data["hosts"][host]['keyvals'],
                    )
            # Parse Groups into objects:
            logging.debug("Parsing groups into objects")
            for group in self._data["groups"]:
                self._data["groups"][group] = Group(
                    hosts=self._data["groups"][group]['hosts'],
                    children=self._data["groups"][group]['children'],
                    ippools=self._data["groups"][group]['ippools'],
                    )
            # Check if somebody did not mess with the inventory:
            if self._data["_meta"]["checksum"] != checksum:
                # FIXME - later it can be divided into recalculating only the
                # sections that changed.
                logging.warning("File checksum mismatch, manual edition detected!")
                self.recalculate_inventory()
            logging.debug("Inventory {0} has been loaded.".format(
                          self._inventory_path))

    def _ippool_overlaps(self, other=None):
        """Check if two ip pool overlap

        Depending on orguments, this method checks all ip pools or just selected
        one for conflicts with other ip pools.

        Args:
            other: ip pool to check, None if checking all IP pools is desired

        Raises:
            BadDataException if ip pool/pools overlap, None otherwise
        """
        logging.info("Checking for overlapping ip pools")
        if other is not None:
            for tmp in self._data["ippools"]:
                if other.overlaps(self._data["ippools"][tmp]):
                    msg = "Ippool {0} overlaps ".format(other)
                    msg += "with {0}".format(self._data["ippools"][tmp])
                    raise MalformedInputException(msg)
        else:
            # Check for all ippools for conflicts:
            # Simple n^2 algorithm, divide-an-conquer has 0.5(n^2-n) ~= O(n^2).
            # FIXME - add sorting the table first!
            tmp = list(self._data["ippools"].keys())
            size = len(tmp)
            for i in range(size - 1):
                for j in range(i+1, size):
                    if self._data["ippools"][tmp[i]].overlaps(
                            self._data["ippools"][tmp[j]]):
                        msg = "Ippool {0} overlaps with {0}".format(tmp[i], tmp[j])
                        raise BadDataException(msg)

    def _ippool_refresh(self):
        """Recreate ip pool usage data.

        This method re-creates usage data for ip pools by checking *each
        and every* ip assigned to host whether it is covered by some ip
        pool already or not.

        This is costly, but fortunatelly, this function will be called only if
        manual changes to the inventory were detected.
        """
        # FIXME - add sorting the table first to go below n^2!
        logging.info("Recalculating ip pools usage")
        for ippool in self._data["ippools"]:  # ~100
            self._data["ippools"][ippool].release_all()
            for host in self._data["hosts"]:  # ~1000
                for var in KeyWordValidator.get_ipaddress_keywords():
                    ip = self._data['hosts'][host].get_keyval(var, reporting=False)
                    if ip is not None and ip in self._data["ippools"][ippool]:
                        self._data["ippools"][ippool].allocate(ip)

    def _groups_cleanup(self):
        """Remove child groups that no longer exist"""
        logging.info("Cleaning up stale groups if any")
        for group in self._data['groups']:
            for child in self._data['groups'][group].get_children():
                if child not in self._data['groups']:
                    logging.debug("Removing stale child group {0} from {1}".format(
                                  group, child))
                    self._data['groups'][group].del_child(child)

    def _hosts_cleanup(self):
        """Cleanup hosts data.

        This method removes hosts that no longer exist from groups, and
        also tries to normalize hostnames and aliases.
        """
        logging.info("Normalizing host names and aliases")
        for host in self._data['hosts']:
            for alias in self._data['hosts'][host].get_aliases():
                alias_n = Host.normalize_hostname(alias)
                if alias != alias_n:
                    msg = "Non-standard alias detected: {0} vs {1} for host {2}, fixing"
                    logging.warn(msg.format(alias, alias_n, host))
                    host = self._data['hosts'][host]
                    host.alias_del(alias)
                    host.alias_add(alias_n)
            host_n = Host.normalize_hostname(host)
            if host != host_n:
                msg = "Non-standard hostname detected: {0} vs {1}, renaming"
                logging.warn(msg.format(host, host_n))
                self.host_rename(host, host_n)

        logging.info("Cleaning up stale hosts if any")
        for group in self._data['groups']:
            for host in self._data['groups'][group].get_hosts():
                if host not in self._data['hosts']:
                    logging.debug("Removing stale host {0} from group {1}".format(
                                  host, group))
                    self._data['groups'][group].del_host(host)

    def _ippool_find_and_assign(self, ip):
        """Assign orphaned ips to ip pools

        Find ippools that contain given ip and mark it as assigned. Break after
        first match thanks to ip pool overlap checking - there will be only
        one match.

        Args:
            ip: orphaned ip which should be assigned to ip pool
        """
        for ippool in self._data["ippools"]:
            if ip in self._data["ippools"][ippool]:
                self._data["ippools"][ippool].allocate(ip)
                break

    def _ippool_find_and_deallocate(self, ip):
        """Find IP pool given ip belongs to and deallocate it.

        Find ippools that contain given ip and mark it as free. Break after
        first match thanks to ip pool overlap checking - there will be only
        one match.

        Args:
            ip: ip to allocate
        """
        for ippool in self._data["ippools"]:
            if ip in self._data["ippools"][ippool]:
                self._data["ippools"][ippool].release(ip)
                break

    def is_recalculated(self):
        """Check if inventory was recalculated.

        Returns:
            True if inventory was recalculated and need saving, False
            otherwise.
        """
        return self._is_recalculated

    def host_to_groups(self, host):
        """Find groups that given host belongs to."""
        ret = []
        for group in self._data['groups']:
            if self._data['groups'][group].has_host(host):
                ret.append(group)
        return ret

    def recalculate_inventory(self):
        """Recheck/recalaculate inventory

        This method makes sure that inventory is sane and coherent by
        calling internal cleanup functions.
        """
        self._ippool_overlaps()
        self._ippool_refresh()
        self._groups_cleanup()
        self._hosts_cleanup()
        self._is_recalculated = True

    def save(self):
        """Serialize object and save it in human-readable format

        Using .get_hash() methods, iterate over each and every object this
        inventory contains and fetch object's data. Then, save the data in
        YAML format so that users can also edit inventory by hand.

        It should be noted that this approach complicates stuff - pickle module
        could have been used without introducing additional boilerplate, but
        it is desirable to have a way to easily compare the changes using git-diff
        and allow users to inspect changes introduced by the tool.

        Raises:
            IOError: there has been a problem with saving serialized data.
        """
        ret = {"ippools": {},
               "hosts": {},
               "groups": {},
               }
        for ippool in self._data["ippools"]:
            ret["ippools"][ippool] = self._data["ippools"][ippool].get_hash()
        for host in self._data['hosts']:
            ret["hosts"][host] = self._data['hosts'][host].get_hash()
        for group in self._data['groups']:
            ret["groups"][group] = self._data['groups'][group].get_hash()

        tmp = yaml.dump(ret, Dumper=Dumper, encoding='utf-8',
                        default_flow_style=False)
        checksum = hashlib.sha256(tmp).hexdigest()
        logging.debug("Serialized hosts data is {0} bytes, ".format(len(tmp)) +
                      "checksum is {0}.".format(checksum))

        ret["_meta"] = {"version": MIN_SUPPORTED_INVENTORY_FORMAT,
                        "checksum": checksum, }

        with open(self._inventory_path, 'wb') as fh:
            yaml.dump(ret, stream=fh, Dumper=Dumper, encoding='utf-8',
                      default_flow_style=False)

    def get_ansible_inventory(self):
        """Provide inventory data in format digestable by ansible

        This function shallow-copies inventory data and reorganizes it in a way
        that it makes it usable for "--list" option used by ansible. It also masks
        some internal data that is not needed by Ansible itself, and should be
        considered private, and it provides "all" group that contains all the
        host in the inventory.

        Return:
            A hash that conforms to:
               http://docs.ansible.com/developing_inventory.html#tuning-the-external-inventory-script

            Please read the document for more details.
        """
        ret = {"_meta": {"hostvars": {}}}
        for host in self._data['hosts']:
            keyvals = self._data['hosts'][host].get_keyval()
            # ansible_ssh_host key is mandatory:
            if "ansible_ssh_host" not in keyvals:
                msg = "Host {0} does not provide ".format(host)
                msg += "ansible_ssh_host variable."
                raise BadDataException(msg)
            ret["_meta"]["hostvars"][host] = {}
            for key in keyvals:
                if key in KeyWordValidator.get_ipaddress_keywords() + \
                        KeyWordValidator.get_ipnetwork_keywords():
                    ret["_meta"]["hostvars"][host][key] = str(keyvals[key])
                else:
                    ret["_meta"]["hostvars"][host][key] = keyvals[key]
        for group in self._data['groups']:
            ret[group] = {"hosts": self._data['groups'][group].get_hosts(),
                          "vars": {},
                          "children": self._data["groups"][group].get_children(), }
        # Add special "all group" to which all hosts belong:
        ret["all"] = {"hosts": list(self._data['hosts']),
                      "vars": {},
                      "children": []}

        return ret

    def ippool_add(self, pool, pool_obj):
        """Add new ip pool object to inventory

        Args:
            pool: name of the pool
            pool_object: an IPPool object

        Raises:
            MalformedInputException: ip pool with given name already exists
        """
        self._ippool_overlaps(pool_obj)
        if pool not in self._data['ippools']:
            self._data['ippools'][pool] = pool_obj
        else:
            raise MalformedInputException("Ippool with name {0}".format(pool) +
                                          "already exists!")

    def ippool_del(self, pool):
        """Delete pool

        Args:
            pool: name of the ip pool to delete

        Raises:
            MalformedInputException: pool with given name does not exist
        """
        if pool not in self._data['ippools']:
            msg = "IP Pool {0} does not exist".format(pool)
            raise MalformedInputException(msg)
        else:
            for group in self._data['groups']:
                self._data['groups'][group].del_pool_by_pool(
                    self._data['ippools'][pool])
            del self._data['ippools'][pool]

    def ippool_get(self, pool=None):
        """Fetch IPPool object

        Args:
            name of the IPPool to fetch

        Raises:
            MalformedInputException: pool with given name does not exist
        """
        if pool is not None:
            if pool not in self._data['ippools']:
                msg = "IP Pool {0} does not exist".format(pool)
                raise MalformedInputException(msg)
            else:
                return self._data['ippools'][pool]
        else:
            # Create a shallow copy of the internal data
            return list(self._data['ippools'])

    def ippool_assign(self, pool, group, pool_related_var):
        """Assign pool to group via keyval var

        Args:
            pool: name of the pool to assign
            pool_related_var: keyval that shoul use given pool for ip address
                auto-assignement
            group: name of the group given pool should be assigned to

        Raises:
            MalformedInputException: input data is malformed
        """
        if group not in self._data['groups']:
            msg = "Group with name {0} does not exist!".format(group)
            raise MalformedInputException(msg)
        elif pool not in self._data['ippools']:
            msg = "IP pool with name {0} does not exist!".format(pool)
            raise MalformedInputException(msg)
        else:
            self._data['groups'][group].set_pool(var=pool_related_var,
                                                 name=pool)

    def ippool_revoke(self, pool, group, pool_related_var):
        """Revoke pool from group

        Args:
            pool: name of the pool to revoke
            pool_related_var: keyval that has been using given pool for ip address
                auto-assignement
            group: name of the group given pool should be revoked from
        """
        if group not in self._data['groups']:
            logging.debug("Ignoring an attemtp to remove ip pool from " +
                          "inexistant group {0}".format(group))
        else:
            self._data['groups'][group].del_pool_by_var(var=pool_related_var)

    def ippool_book_ipaddr(self, pool, ipaddr):
        """Exclude an ip address from the ip pool

        This is just a thin wrapper around IPPool.book().

        Args:
            pool: name of the ip pool where ip address should be booked
            ipaddr: ipaddress.ip_address object which should be booked

        Raises:
            MalformedInputException: input data is malformed
        """
        if pool not in self._data['ippools']:
            raise MalformedInputException("IP Pool {0} does not exist".format(pool))
        else:
            self._data['ippools'][pool].book(ipaddr)

    def ippool_cancel_ipaddr(self, pool, ipaddr):
        """Cancel exclusion of an ip address from the ip pool

        This is just a thin wrapper around IPPool.cancel().

        Args:
            pool: name of the ip pool where ip address should be canceled
            ipaddr: ipaddress.ip_address object which should be canceled

        Raises:
            MalformedInputException: input data is malformed
        """
        if pool not in self._data['ippools']:
            raise MalformedInputException("IP Pool {0} does not exist".format(pool))
        else:
            self._data['ippools'][pool].cancel(ipaddr)

    def group_add(self, group):
        """Add a new group to inventory.

        Args:
            group: name of the new group

        Raises:
            MalformedInputException: group with such name already exists
        """
        if group not in self._data['groups']:
            self._data['groups'][group] = Group()
        else:
            raise MalformedInputException("Group {0} already exists!".format(group))

    def group_del(self, group):
        """Delete the group to inventory.

        This method also takes care of removing given group from other groups,
        if it was a child group.

        Args:
            group: name of the group to delete

        Raises:
            MalformedInputException: group with such name does not exists already
        """
        if group in self._data['groups']:
            del self._data['groups'][group]
            # Remove the group from other groups (==remove it from children
            # list):
            for p_group in self._data['groups']:
                self._data['groups'][p_group].del_child(group, reporting=False)
        else:
            raise MalformedInputException("Group {0} does not exist!".format(group))

    def group_get(self, group=None):
        """Get a Group object identified by name.

        Args:
            group: name of the group to get, or None if all object names should
                returned

        Returns:
            Depending on the value of group param, either all object *names* are
            returned, or the *object* identified by group param

        Raises:
            MalformedInputException: group with given name does not exists.
        """
        if group is not None:
            if group not in self._data['groups']:
                msg = "Group {0} does not exist".format(group)
                raise MalformedInputException(msg)
            else:
                return self._data['groups'][group]
        else:
            # Create a shallow copy of the internal data
            return list(self._data['groups'])

    def group_child_add(self, group, child):
        """Add a child group to group

        Args:
            group: name of the group to add child to
            child: name of the child group

        Raises:
            MalformedInputException: either child group or a parent group does
                not exists.
        """
        if group in self._data['groups']:
            if child in self._data['groups']:
                self._data['groups'][group].add_child(child)
            else:
                msg = "Child group {0} does not exist!".format(child)
                raise MalformedInputException(msg)
        else:
            raise MalformedInputException("Group {0} does not exist!".format(group))

    def group_child_del(self, group, child):
        """Remove a child group from a group

        Args:
            group: name of the group to remove child from
            child: name of the child group

        Raises:
            MalformedInputException: either child group or a parent group does
                exists
        """
        if group in self._data['groups']:
            self._data['groups'][group].del_child(child)
        else:
            msg = "Group with name {0} does not exist!".format(group)
            raise MalformedInputException(msg)

    def group_host_add(self, group, host):
        """Add a host to a group

        Args:
            host: name of the host
            group: name of the group

        Raises:
            MalformedInputException: either host or group does not exist, or
                host name is malformed.
        """
        if group in self._data['groups']:
            host_n = Host.normalize_hostname(host)
            if host_n in self._data['hosts']:
                self._data['groups'][group].add_host(host_n)
            else:
                msg = "Host {0} does not exist!".format(host_n)
                raise MalformedInputException(msg)
        else:
            msg = "Group {0} does not exist!".format(group)
            raise MalformedInputException(msg)

    def group_host_del(self, group, host):
        """Remove a host from a group

        Args:
            host: name of the host
            group: name of the group

        Raises:
            MalformedInputException: either host or group does not exist
        """
        if group in self._data['groups']:
            self._data['groups'][group].del_host(host)
        else:
            msg = "Group with name {0} does not exist!".format(group)
            raise MalformedInputException(msg)

    def host_get(self, host=None):
        """Get a Host object identified by name.

        Args:
            host: name of the host to get, or None if all object names should
                returned

        Returns:
            Depending on the value of group param, either all object *names* are
            returned, or the *object* identified by group param

        Raises:
            MalformedInputException: host with given name does not exists or is
                malformed.
        """
        if host is not None:
            host_n = Host.normalize_hostname(host)
            if host_n not in self._data['hosts']:
                msg = "Host {0} does not exist".format(host_n)
                raise MalformedInputException(msg)
            else:
                return self._data['hosts'][host_n]
        else:
            # Create a shallow copy of the internal data
            return list(self._data['hosts'])

    def host_add(self, host):
        """Add a host to inventory

        This method simply creates new Host object identified by "host" name
        object in the inventory.

        Args:
            host: name of the new host

        Raises:
            MalformedInputException: host with that name already exists, or is
                malformed
        """
        host_n = Host.normalize_hostname(host)
        if host_n not in self._data['hosts']:
            for tmp in self._data['hosts']:
                if self._data['hosts'][tmp].get_aliases(alias=host_n, reporting=False):
                    msg = "Host {0} already has alias with the name of new host"
                    raise MalformedInputException(msg.format(tmp))
            self._data['hosts'][host_n] = Host()
        else:
            raise MalformedInputException("Host {0} already exist!".format(host_n))

    def host_del(self, host):
        """Delete host from inventory

        This method deltes host from inventory, and removes it from all the groups
        it was member of.

        Args:
            host: name of the host to remove

        Raises:
            MalformedInputException: host with given name does not exists, or is
                malformed
        """
        host_n = Host.normalize_hostname(host)
        if host_n in self._data['hosts']:
            # Remove the host from all groups:
            for group in self._data['groups']:
                self._data['groups'][group].del_host(host_n, reporting=False)
            # Remove host's IP from all ip pools:
            for ippool in self._data["ippools"]:
                for var in KeyWordValidator.get_ipaddress_keywords():
                    ip = self._data['hosts'][host].get_keyval(var, reporting=False)
                    if ip is not None and ip in self._data["ippools"][ippool]:
                        self._data["ippools"][ippool].release(ip)
            # And finally remove the host itself
            del self._data['hosts'][host_n]
        else:
            raise MalformedInputException("Host {0} does not exist!".format(host_n))

    def host_set_vars(self, host, data):
        """Set keyval parameter for a host.

        This method sets a keyval argument for given host. In case of plain
        variables, that do not involve ip address resources, it simply sets
        keyvals using Host.set_keyval().

        When the keyval involves ip addresses, it takes care of auto-assignement,
        if value has not been provided (==user asked for auto assignement) or
        simply marks given IP as allocated so that it is not auto-assigned later
        on.

        Args:
            host: name of the host keyval should be assigned to
            data: a list of hashes with two keys:
                {"key": key of the variable, "val": variable's value}

        Raises:
            MalformedInputException: provided data does not make sense.
        """
        host_n = Host.normalize_hostname(host)
        if host_n in self._data['hosts']:
            for keyval in data:
                if KeyWordValidator.is_ipaddress_keyword(keyval["key"]):
                    # First, lets deallocate old ip (if any):
                    ip = self._data['hosts'][host_n].get_keyval(keyval["key"],
                                                                reporting=False)
                    if ip is not None:
                        self._ippool_find_and_deallocate(ip)
                    if keyval["val"] is None:
                        # Lets find a group with a pool capable of assigning an
                        # address to us
                        groups = self.host_to_groups(host_n)
                        ippool = None
                        for group in groups:
                            tmp = self._data['groups'][group].get_pool(keyval["key"])
                            if tmp is not None and ippool is None:
                                ippool = tmp
                            else:
                                msg = "Host {0} may get ip for var {1} "
                                msg += "from more than one ippool: {2} <-> {3}"
                                MalformedInputException(msg.format(
                                    host_n, keyval["key"], tmp, ippool))
                        if ippool is None:
                            msg = "There are no ippools suitable for assigning"
                            msg += " an IP to " + keyval["key"] + " variable for"
                            msg += " this host"
                            raise MalformedInputException(msg)
                        else:
                            keyval["val"] = \
                                self._data['ippools'][ippool].allocate()
                    else:
                        self._ippool_find_and_assign(keyval["val"])
                self._data['hosts'][host_n].set_keyval(keyval)
        else:
            raise MalformedInputException("Host {0} does not exist!".format(host_n))

    def host_del_vars(self, host, keys):
        """Remove a keyval from host

        Removes a keyval from host object and takes care of deallocating ip
        addresses from ip pools if applicable.

        Args:
            host: name of the host keyval should be removed from
            key: keys used to identify keyvals destined for deletion

        Raises:
            MalformedInputException: host or key with given name does not exists,
                or host is malformed
        """
        host_n = Host.normalize_hostname(host)
        if host_n in self._data['hosts']:
            for key in keys:
                if KeyWordValidator.is_ipaddress_keyword(key):
                    # First, lets deallocate old ip (if any):
                    ip = self._data['hosts'][host_n].get_keyval(key, reporting=False)
                    if ip is not None:
                        self._ippool_find_and_deallocate(ip)
                self._data['hosts'][host_n].del_keyval(key)
        else:
            raise MalformedInputException("Host {0} does not exist!".format(host_n))

    def host_alias_add(self, host, alias):
        """Assign an alias to the host

        Add an alias to a host, but first check whether it has not been assigned
        yet, either as a hostname or some other alias.

        Raises:
            MalformedInputException: either host to which alias should be assigned
                does not exists, or a host/alias with such name already exists,
                or host/alias are malformed.
        """
        host_n = Host.normalize_hostname(host)
        if host_n in self._data['hosts']:
            alias_n = Host.normalize_hostname(alias)
            if alias_n not in self._data['hosts']:
                for tmp in self._data['hosts']:
                    if self._data['hosts'][tmp].get_aliases(alias_n, reporting=False):
                        msg = "Alias {0} is already assigned to host {1}"
                        raise MalformedInputException(msg.format(alias_n, tmp))
                else:
                    self._data['hosts'][host_n].alias_add(alias_n)
            else:
                msg = "There exists host with the same name as an alias {0}."
                MalformedInputException(msg.format(alias_n))
        else:
            raise MalformedInputException("Host {0} does not exist!".format(host_n))

    def host_alias_del(self, host, alias):
        """Remove an alias from the host

        Args:
            alias: name of the alias to remove

        Raises:
            MalformedInputException: either alias or host does not exist, or are
                malformed.
        """
        host_n = Host.normalize_hostname(host)
        if host_n in self._data['hosts']:
            self._data['hosts'][host_n].alias_del(alias)
        else:
            raise MalformedInputException("Host {0} does not exist!".format(host))

    def host_rename(self, host_old, host_new):
        """Rename a host

        Args:
            host_old: old hostname
            host_new: new hostname

        Raises:
            MalformedInputException: host_old does not exist, or both hostnames
                are malformed.
        """
        # Sanity checking first:
        if host_old not in self._data['hosts']:
            msg = "Host {0} does not exist, and thus cannot be renamed"
            raise MalformedInputException(msg.format(host_old))
        host_new_n = Host.normalize_hostname(host_new)

        # First, lets rename it in "hosts" hash:
        self._data['hosts'][host_new_n] = self._data['hosts'].pop(host_old)

        # And now lets rename all references in groups:
        for group in self._data['groups']:
            try:
                self._data['groups'][group].del_host(host_old)
            except MalformedInputException:
                pass
            else:
                self._data['groups'][group].add_host(host_new_n)


def main(args, inventory_path, backend_domain, extra_ipaddress_keywords=[],
         extra_ipnetwork_keywords=[], extra_integer_keywords=[]):
    """Main body of the inventory tool

    This function takes care of routing of parsed command line arguments to
    correct object methods, and set's up some basic housekeeping, including
    saving/restoring inventory.

    Args:
        inventory_path: name of the inventory file to use
    """

    if not backend_domain:
        msg = "Backend domain parameter needs to be provided. "
        msg += "Please fix your config"
        print(msg)
        sys.exit(1)

    Host.set_backend_domain(backend_domain)
    KeyWordValidator.set_extra_ipaddress_keywords(extra_ipaddress_keywords)
    KeyWordValidator.set_extra_ipnetwork_keywords(extra_ipnetwork_keywords)
    KeyWordValidator.set_extra_integer_keywords(extra_integer_keywords)

    config = parse_commandline(script_path=args[0], commandline=args[1:])

    # Setup some basic logging:
    logger = logging.getLogger()
    if not config.std_err:
        # Print/log only important stuff:
        logger.setLevel(logging.WARN)
        fmt = logging.Formatter('%(message)s')
    else:
        if not config.verbose:
            # Print most of the stuff:
            logger.setLevel(logging.INFO)
            fmt = logging.Formatter('%(levelname)s: %(message)s')
        else:
            # Here be dragons:
            logger.setLevel(logging.DEBUG)
            fmt = logging.Formatter('%(filename)s[%(process)d] ' +
                                    '%(levelname)s: %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    # Say hello!
    logging.debug("{0} is starting, config: {1}, inventory_path: {2}".format(
                  __file__, str(config), inventory_path))

    try:
        # Initialize our main data object:
        try:
            # initialize=False shares the same path for simplicity's sake, even
            # though it does not drop any exception.
            inventory = InventoryData(inventory_path,
                                      initialize=config.initialize_inventory)
        except IOError as e:
            logging.error("Failed to open inventory file {0}: {1}".format(
                          inventory_path, str(e)))
            sys.exit(1)
        except yaml.YAMLError as e:
            logging.error("Inventory file {0} is not a proper YAML document: {1}".format(
                          inventory_path, str(e)))
            sys.exit(1)

        # Do some stuff:
        save_data = False

        if config.list:
            logging.debug("Dumping whole inventory to Json")
            res = inventory.get_ansible_inventory()
            save_data = inventory.is_recalculated()
            print(json.dumps(res, sort_keys=True, indent=4, separators=(',', ': ')))
        elif config.subcommand == 'ippool':
            if config.add is not None:
                inventory.ippool_add(pool=config.ippool_name,
                                     pool_obj=config.add)
                save_data = True
            elif config.delete:
                inventory.ippool_del(pool=config.ippool_name)
                save_data = True
            elif config.show:
                # Detailed info about ippool
                data = inventory.ippool_get(pool=config.ippool_name)
                print(str(data))
            elif config.list_all:
                # Just list the names of available ippools
                data = inventory.ippool_get()
                for key in data:
                    print(key)
            elif config.assign is not None:
                inventory.ippool_assign(pool=config.ippool_name,
                                        group=config.assign[0],
                                        pool_related_var=config.assign[1])
                save_data = True
            elif config.revoke is not None:
                inventory.ippool_revoke(group=config.revoke[0],
                                        pool_related_var=config.revoke[1])
            elif config.book is not None:
                inventory.ippool_book_ipaddr(pool=config.ippool_name,
                                             ipaddr=config.book)
                save_data = True
            elif config.cancel is not None:
                inventory.ippool_cancel_ipaddr(pool=config.ippool_name,
                                               ipaddr=config.book)
                save_data = True
        elif config.subcommand == 'group':
            if config.add:
                inventory.group_add(group=config.group_name)
                save_data = True
            elif config.delete:
                inventory.group_del(group=config.group_name)
                save_data = True
            elif config.show:
                # Detailed info about group
                data = inventory.group_get(group=config.group_name)
                print(str(data))
            elif config.list_all:
                # Just list the names of available groups
                data = inventory.group_get()
                for key in data:
                    print(key)
            elif config.child_add is not None:
                inventory.group_child_add(group=config.group_name,
                                          child=config.child_add)
                save_data = True
            elif config.child_del is not None:
                inventory.group_child_del(group=config.group_name,
                                          child=config.child_del)
                save_data = True
            elif config.host_add is not None:
                inventory.group_host_add(group=config.group_name,
                                         host=config.host_add)
                save_data = True
            elif config.host_del is not None:
                inventory.group_host_del(group=config.group_name,
                                         host=config.host_del)
                save_data = True
        elif config.subcommand == 'host':
            if config.add:
                inventory.host_add(host=config.host_name)
                save_data = True
            elif config.delete:
                inventory.host_del(host=config.host_name)
                save_data = True
            elif config.show:
                # Detailed info about host
                data = inventory.host_get(host=config.host_name)
                print(str(data))
            elif config.list_all:
                data = inventory.host_get()
                for key in data:
                    print(key)
            elif config.var_set is not None:
                inventory.host_set_vars(host=config.host_name,
                                        data=config.var_set)
                save_data = True
            elif config.var_del is not None:
                inventory.host_del_vars(host=config.host_name,
                                        keys=config.var_del)
                save_data = True
            elif config.alias_add is not None:
                inventory.host_alias_add(host=config.host_name,
                                         alias=config.alias_add)
                save_data = True
            elif config.alias_del is not None:
                inventory.host_alias_del(host=config.host_name,
                                         alias=config.alias_del)
                save_data = True
    except ScriptException as e:
        logging.error(str(e))
        sys.exit(1)

    # Write updated inventory back, if necessary:
    if save_data or config.initialize_inventory:
        try:
            inventory.save()
        except IOError as e:
            logging.error("Failed to save inventory file " +
                          "{0}: {1}".format(inventory_path, str(e)))
            sys.exit(1)
    sys.exit(0)
