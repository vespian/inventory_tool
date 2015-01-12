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

import os.path as op

#Where am I ?
_module_dir = op.dirname(op.realpath(__file__))
_main_dir = op.abspath(op.join(_module_dir, '..'))
_fabric_base_dir = op.join(_main_dir, 'fabric/')

#Configfile location
TEST_INVENTORY = op.join(_fabric_base_dir, 'hosts-production.yml')
OVERLAPPING_IPPOOLS_INVENTORY = op.join(_fabric_base_dir, 'overlapping-ippools.yml')
NONOVERLAPPING_IPPOOLS_INVENTORY = op.join(_fabric_base_dir, 'nonoverlapping-ippools.yml')
REFRESHED_IPPOOL_INVENTORY = op.join(_fabric_base_dir, 'refreshed-ippool.yml')
ORPHANED_CHILD_GORUPS_INVENTORY = op.join(_fabric_base_dir, 'orphaned-child-groups.yml')
ORPHANED_HOSTS_INVENTORY = op.join(_fabric_base_dir, 'orphaned-hosts.yml')
EMPTY_CHECKSUM_OK_INVENTORY = op.join(_fabric_base_dir, 'empty_checksum_ok.yml')
EMPTY_CHECKSUM_BAD_INVENTORY = op.join(_fabric_base_dir, 'empty_checksum_bad.yml')
DENORMALIZED_ALIASES_INVENTORY = op.join(_fabric_base_dir, 'denormalized-aliases.yml')
DENORMALIZED_HOSTNAMES_INVENTORY = op.join(_fabric_base_dir, 'denormalized-hostnames.yml')
TMP_INVENTORY = op.join(_fabric_base_dir, 'tmp.yml')
MISSING_ANSIBLE_SSH_HOST_INVENTORY = op.join(_fabric_base_dir, 'missing_ansible_ssh_host.yml')
HOSTVARS_INVENTORY = op.join(_fabric_base_dir, 'hostvars.yml')
IPADDR_AUTOALLOCATION_INVENTORY = op.join(_fabric_base_dir, 'ipaddr-autoallocation.yml')
CHILD_GROUPS_INVENTORY = op.join(_fabric_base_dir, 'child-groups.yml')
