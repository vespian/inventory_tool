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

from inventory_tool.exception import MalformedInputException, GenericException

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
            msg = "An attempt to release an ip {0} ".format(ip)
            msg += "which has not been allocated yet."
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
        elif ip in self._reserved:
            msg = "IP {0} has already been booked".format(ip)
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
        else:
            msg = "Could not determine membership of the object {0}".format(other)
            raise MalformedInputException(msg)

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
        return msg
