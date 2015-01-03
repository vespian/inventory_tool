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
import json
import logging
import logging.handlers
import sys
import yaml

import inventory_tool
from inventory_tool.exception import ScriptException
from inventory_tool.object.host import Host
from inventory_tool.object.inventory import InventoryData
from inventory_tool.validators import KeyWordValidator, HostnameParser
from inventory_tool.validators import get_name, get_ippool, get_ipaddr, get_fqdn, get_keyval


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

    HostnameParser.set_backend_domain(backend_domain)
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
        elif 'subcommand' in config and config.subcommand == 'ippool':
            if any([config.add, config.assign, config.revoke, config.book,
                    config.cancel]):
                if config.add is not None:
                    inventory.ippool_add(pool=config.ippool_name,
                                         pool_obj=config.add)
                    save_data = True
                if config.assign is not None:
                    inventory.ippool_assign(pool=config.ippool_name,
                                            group=config.assign[0],
                                            pool_related_var=config.assign[1])
                    save_data = True
                if config.revoke is not None:
                    inventory.ippool_revoke(group=config.revoke[0],
                                            pool_related_var=config.revoke[1])
                if config.book is not None:
                    inventory.ippool_book_ipaddr(pool=config.ippool_name,
                                                 ipaddr=config.book)
                    save_data = True
                if config.cancel is not None:
                    inventory.ippool_cancel_ipaddr(pool=config.ippool_name,
                                                   ipaddr=config.book)
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
        elif 'subcommand' in config and config.subcommand == 'group':
            if any([config.add, config.child_add, config.child_del,
                    config.host_add, config.host_del]):
                if config.add:
                    inventory.group_add(group=config.group_name)
                    save_data = True
                if config.child_add is not None:
                    inventory.group_child_add(group=config.group_name,
                                              child=config.child_add)
                    save_data = True
                if config.child_del is not None:
                    inventory.group_child_del(group=config.group_name,
                                              child=config.child_del)
                    save_data = True
                if config.host_add is not None:
                    inventory.group_host_add(group=config.group_name,
                                             host=config.host_add)
                    save_data = True
                if config.host_del is not None:
                    inventory.group_host_del(group=config.group_name,
                                             host=config.host_del)
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
        elif 'subcommand' in config and config.subcommand == 'host':
            if any([config.add, config.var_set, config.var_del,
                    config.alias_add, config.alias_del, config.group_add,
                    config.group_del]):
                if config.add:
                    inventory.host_add(host=config.host_name)
                    save_data = True
                if config.group_add is not None:
                    for group in config.group_add:
                        inventory.group_host_add(host=config.host_name,
                                                 group=group)
                    save_data = True
                if config.group_del is not None:
                    for group in config.group_del:
                        inventory.group_host_del(host=config.host_name,
                                                 group=group)
                    save_data = True
                if config.var_set is not None:
                    inventory.host_set_vars(host=config.host_name,
                                            data=config.var_set)
                    save_data = True
                if config.var_del is not None:
                    inventory.host_del_vars(host=config.host_name,
                                            keys=config.var_del)
                    save_data = True
                if config.alias_add is not None:
                    inventory.host_alias_add(host=config.host_name,
                                             alias=config.alias_add)
                    save_data = True
                if config.alias_del is not None:
                    inventory.host_alias_del(host=config.host_name,
                                             alias=config.alias_del)
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
        version=inventory_tool.__version__)
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
    parser_ippool.add_argument(
        "-a", "--add",
        action="store",
        type=get_ippool,
        metavar="network",
        help="Add a new ippool.",)
    parser_ippool.add_argument(
        "-d", "--delete",
        action="store_true",
        default=False,
        help="Delete an ippool",)
    parser_ippool.add_argument(
        "-i", "--assign",
        action="store",
        nargs=2,
        type=get_name,
        metavar=("group-name", "retlated-var-name"),
        help="Assign the ippool to a group",)
    parser_ippool.add_argument(
        "-r", "--revoke",
        action="store",
        nargs=2,
        type=get_name,
        metavar=("group-name", "retlated-var-name"),
        help="Revoke the ippool from a group",)
    parser_ippool.add_argument(
        "-b", "--book",
        action="store",
        type=get_ipaddr,
        metavar="ip-address",
        help="Reserve an ip addres for future use.",)
    parser_ippool.add_argument(
        "-c", "--cancel",
        action="store",
        type=get_ipaddr,
        metavar="ip-address",
        help="Restore to the pool an ip address reserved by -b/--book option.")
    mutexgroup_ippool = parser_ippool.add_mutually_exclusive_group(required=False)
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
    parser_group.add_argument(
        "-a", "--add",
        action="store_true",
        default=False,
        help="Add a new group.",)
    parser_group.add_argument(
        "-d", "--delete",
        action="store_true",
        default=False,
        help="Delete a group",)
    parser_group.add_argument(
        "--child-add",
        action="store",
        type=get_name,
        metavar="child-name",
        help="Add a child group to the group",)
    parser_group.add_argument(
        "--child-del",
        action="store",
        type=get_name,
        metavar="child-name",
        help="Delete a child group from the group",)
    parser_group.add_argument(
        "--host-add",
        action="store",
        type=get_name,
        metavar="host-name",
        help="Add a host to the group",)
    parser_group.add_argument(
        "--host-del",
        action="store",
        type=get_name,
        metavar="host-name",
        help="Delete a host from the group",)
    mutexgroup_group = parser_group.add_mutually_exclusive_group(required=False)
    mutexgroup_group.add_argument(
        "-s", "--show",
        action="store_true",
        default=False,
        help="Show group's children and member hosts.",)
    mutexgroup_group.add_argument(
        "-l", "--list-all",
        action='store_true',
        default=False,
        help="List all available groups.")

    # Host related
    parser_host = subparsers.add_parser("host",
                                        help="Host manipulation.")
    parser_host.add_argument(
        "-n", "--host-name",
        action='store',
        type=get_fqdn,
        help="Name of the host to work with.")
    parser_host.add_argument(
        "-a", "--add",
        action="store_true",
        default=False,
        help="Add a new host.",)
    parser_host.add_argument(
        "-d", "--delete",
        action="store_true",
        default=False,
        help="Delete a host",)
    parser_host.add_argument(
        "--var-set",
        action="store",
        type=get_keyval,
        nargs="+",
        metavar="key:val",
        help="Add a key:val pair to host. Depending on the key, val may be " +
             "optional")
    parser_host.add_argument(
        "--var-del",
        action="store",
        type=get_name,
        nargs="+",
        metavar="key",
        help="Delete a key:val pairs from the host data.",)
    parser_host.add_argument(
        "--group-add",
        action="store",
        type=get_name,
        nargs="+",
        metavar="group",
        help="Assign host to a group/groups.",)
    parser_host.add_argument(
        "--group-del",
        action="store",
        type=get_name,
        nargs="+",
        metavar="group",
        help="Remove host from a group/groups.",)
    parser_host.add_argument(
        "--alias-add",
        action="store",
        type=get_fqdn,
        metavar="alias",
        help="Add an alias name to the host.",)
    parser_host.add_argument(
        "--alias-del",
        action="store",
        type=get_fqdn,
        metavar="alias",
        help="Remove an alias from the host.",)
    mutexgroup_host = parser_host.add_mutually_exclusive_group(required=False)
    mutexgroup_host.add_argument(
        "-s", "--show",
        action="store_true",
        default=False,
        help="Show hosts data.",)
    mutexgroup_host.add_argument(
        "-l", "--list-all",
        action="store_true",
        default=False,
        help="List all hosts.",)

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
