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

import sys
import yaml
import hashlib
import logging

import inventory_tool
import inventory_tool.object.group as g
import inventory_tool.object.host as h
import inventory_tool.object.ippool as i
import inventory_tool.validators as v
from inventory_tool.exception import BadDataException, MalformedInputException

# For Python3 < 3.3, ipaddress module is available as an extra module,
# under a different name:
try:
    from ipaddress import ip_address
    from ipaddress import ip_network
except ImportError:
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPNetwork as ip_network

# Try LibYAML first and if unavailable, fall back to pure Python implementation
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    # Logger will not be initialized yet :/
    print("WARNING! libyaml is unavailable, loading slower - pure-python " +
          "implementation of yaml bindings.", file=sys.stderr)
    from yaml import Loader, Dumper


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
                          "_meta": {"version": inventory_tool.MIN_SUPPORTED_INVENTORY_FORMAT,
                                    "checksum": ""},
                          }
            return
        else:
            try:
                with open(self._inventory_path, 'rb') as fh:
                    tmp = fh.read()
            except (OSError, IOError) as e:
                msg = "Failed to open {0}: {1}"
                msg = msg.format(self._inventory_path, str(e))
                raise MalformedInputException(msg)
            self._data = yaml.load(tmp, Loader=Loader)
            # Check if will be able to work with this data:
            if self._data["_meta"]["version"] < \
                    inventory_tool.MIN_SUPPORTED_INVENTORY_FORMAT:
                msg = "Inventory format: {0}, min supported format: {1}".format(
                      self._data["_meta"]["version"],
                      inventory_tool.MIN_SUPPORTED_INVENTORY_FORMAT)
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
                obj = i.IPPool(network=tmp["network"],
                             allocated=tmp["allocated"],
                             reserved=tmp["reserved"],)
                self._data["ippools"][ippool] = obj
            # Parse Hosts into objects:
            logging.debug("Parsing hosts into objects")
            for host in self._data["hosts"]:
                self._data["hosts"][host] = h.Host(
                    aliases=self._data["hosts"][host]['aliases'],
                    keyvals=self._data["hosts"][host]['keyvals'],
                    )
            # Parse Groups into objects:
            logging.debug("Parsing groups into objects")
            for group in self._data["groups"]:
                self._data["groups"][group] = g.Group(
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

        Depending on orguments, this method checks all ip pools or just
        selected one for conflicts with other ip pools.

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
                        msg = "Ippool {0} overlaps with {1}".format(tmp[i], tmp[j])
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
                for var in v.KeyWordValidator.get_ipaddress_keywords():
                    ip = self._data['hosts'][host].get_keyval(var, reporting=False)
                    if ip is not None and ip in self._data["ippools"][ippool]:
                        self._data["ippools"][ippool].allocate(ip_address(ip))

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
                alias_n = v.HostnameParser.normalize_hostname(alias)
                if alias != alias_n:
                    msg = "Non-standard alias detected: {0} vs {1} for host {2}, fixing"
                    logging.warning(msg.format(alias, alias_n, host))
                    host_obj = self._data['hosts'][host]
                    host_obj.alias_del(alias)
                    host_obj.alias_add(alias_n)
            host_n = v.HostnameParser.normalize_hostname(host)
            if host != host_n:
                msg = "Non-standard hostname detected: {0} vs {1}, renaming"
                logging.warning(msg.format(host, host_n))
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

        ret["_meta"] = {"version": inventory_tool.MIN_SUPPORTED_INVENTORY_FORMAT,
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
                if key in v.KeyWordValidator.get_ipaddress_keywords() + \
                        v.KeyWordValidator.get_ipnetwork_keywords():
                    ret["_meta"]["hostvars"][host][key] = str(keyvals[key])
                else:
                    ret["_meta"]["hostvars"][host][key] = keyvals[key]
        for group in self._data['groups']:
            ret[group] = {"hosts": self._data['groups'][group].get_hosts(),
                          "vars": {},
                          "children": self._data["groups"][group].get_children(), }
        # Add special "all group" to which all hosts belong:
        ret["all"] = {"hosts": sorted(self._data['hosts']),
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
            self._data['groups'][group] = g.Group()
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
            host_n = v.HostnameParser.normalize_hostname(host)
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
            host_n = v.HostnameParser.normalize_hostname(host)
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
        host_n = v.HostnameParser.normalize_hostname(host)
        if host_n not in self._data['hosts']:
            for tmp in self._data['hosts']:
                if self._data['hosts'][tmp].get_aliases(alias=host_n, reporting=False):
                    msg = "Host {0} already has alias with the name of new host"
                    raise MalformedInputException(msg.format(tmp))
            self._data['hosts'][host_n] = h.Host()
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
        host_n = v.HostnameParser.normalize_hostname(host)
        if host_n in self._data['hosts']:
            # Remove the host from all groups:
            for group in self._data['groups']:
                self._data['groups'][group].del_host(host_n, reporting=False)
            # Remove host's IP from all ip pools:
            for ippool in self._data["ippools"]:
                for var in v.KeyWordValidator.get_ipaddress_keywords():
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
        host_n = v.HostnameParser.normalize_hostname(host)
        if host_n in self._data['hosts']:
            for keyval in data:
                if v.KeyWordValidator.is_ipaddress_keyword(keyval["key"]):
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
        host_n = v.HostnameParser.normalize_hostname(host)
        if host_n in self._data['hosts']:
            for key in keys:
                if v.KeyWordValidator.is_ipaddress_keyword(key):
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
        host_n = v.HostnameParser.normalize_hostname(host)
        if host_n in self._data['hosts']:
            alias_n = v.HostnameParser.normalize_hostname(alias)
            if alias_n not in self._data['hosts']:
                for tmp in self._data['hosts']:
                    if self._data['hosts'][tmp].get_aliases(alias_n, reporting=False):
                        msg = "Alias {0} is already assigned to host {1}"
                        raise MalformedInputException(msg.format(alias_n, tmp))
                else:
                    self._data['hosts'][host_n].alias_add(alias_n)
            else:
                msg = "There exists host with the same name as an alias {0}."
                raise MalformedInputException(msg.format(alias_n))
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
        host_n = v.HostnameParser.normalize_hostname(host)
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
        host_new_n = v.HostnameParser.normalize_hostname(host_new)

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
