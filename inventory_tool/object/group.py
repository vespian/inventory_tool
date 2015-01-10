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

import logging

from inventory_tool.exception import MalformedInputException
from inventory_tool.validators import HostnameParser


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
            for host in sorted(self._hosts):
                ret += "\t- {0}\n".format(host)
        else:
            ret += "\t<None>\n"
        ret += "Children:\n"
        if self._children:
            for child in sorted(self._children):
                ret += "\t- {0}\n".format(child)
        else:
            ret += "\t<None>\n"
        ret += "Ip pools:\n"
        if self._ippools:
            for var in sorted(self._ippools):
                ret += "\t{0}:{1}\n".format(var, self._ippools[var])
        else:
            ret += "\t<None>\n"
        return ret

    def get_hash(self):
        """Extract data from object in a way suitable for serializing

        Returns:
            Method returns data necessary for re-initializing the same object
            in a form suitable for serialization using YAML/JSON. Normally,
            this object contains other objects which can not be easily
            serialized or are not very readable after serializing.
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
        return sorted(self._children)  # Shallow copy

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
            raise MalformedInputException(
                "Child group {0} could".format(child) +
                " not be found in this group.")

    def has_host(self, host):
        """Check if host belongs to this group"""
        host_n = HostnameParser.normalize_hostname(host)
        return host_n in self._hosts

    def get_hosts(self):
        """Return all the hosts that belong to this group"""
        return sorted(self._hosts)  # Shallow copy

    def add_host(self, host):
        """Add host to group

        Args:
            host: host to add

        Raises:
            MalformedInputException: host has already been added to the group,
                or host name is malformed.
        """
        host_n = HostnameParser.normalize_hostname(host)
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
        host_n = HostnameParser.normalize_hostname(host)
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
        for item in self._ippools.copy().items():
            if item[1] == pool:
                logging.debug("Removing pool by pool {0}:{1}.".format(
                    item[0], item[1]))
                del self._ippools[item[0]]
