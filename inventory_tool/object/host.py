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

import re

from inventory_tool.validators import KeyWordValidator, HostnameParser
from inventory_tool.exception import BadDataException, MalformedInputException

# For Python3 < 3.3, ipaddress module is available as an extra module,
# under a different name:
try:
    from ipaddress import ip_address
    from ipaddress import ip_network
except ImportError:
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPNetwork as ip_network


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
            for alias in sorted(self._aliases):
                ret += "\t- {0}\n".format(alias)
        else:
            ret += "\t<None>\n"
        ret += "Host variables:\n"
        if self._keyvals:
            for keyval in sorted(self._keyvals):
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
        alias_n = HostnameParser.normalize_hostname(alias)
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
        alias_n = HostnameParser.normalize_hostname(alias)
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
