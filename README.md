# Inventory tool

Script intended to augment Ansible's inventory management.

## Motivation

There are couple of reasons why this script has been created.

Firstly, in order prevent chicken and egg problems with DNS, monitoring, net-
working, and other systems, we needed to provide ansible with authoritative
source of ip address information. For example: if DNS fails Ansible is unable
to reconfigure it because it relies on DNS to resolve hosts to connect to. Each
and every host needs to have *ansible_ssh_host* variable set and with thousands
of hosts/containers this scales poorly. High number of files in host_vars/
directory would become hard to manage eventually.

Secondly, a way to address host aliasing sometimes is needed. Given host can be
available under more than one name, and preferably this name should be available
to Ansible (i.e. CNAME entries for zone generation). This once again would have
to end up in host_vars/ directory further complicating management.

Another reason was the fact that we need a way to provision hosts quickly,
and this involves automating ip pools management somehow. Ideally, adding a host
to inventory should trigger assigning it an ip address. Reverse is also true:
removing host from inventory should free its address.

Finally, if we wanted to simply provide a thin wrapper around some centralized
YAML file in our repo, then sooner or later a need for syntax checking and
coherence verification, etc... would arise. As the number of hosts grows, this
would require additional tools.

The script can be easily replaced by some other tool in the future and its data
easily imported.

## Installation

Due to the fact that the Ansible's dynamic inventory interface does not provide
a way to pass parameters and git does not allow symlinks, thin wrapers scripts
have to be provided:
* hosts-production.py
* hosts-dev.py

Wrapper's script task is to store configuration options and locate inventory
file. Then it passes them to the real inventory tool script script by calling
it's *main* method.

The location of the inventory data is done basing on inventory's script name,
current working directory and a constant "data/inventory" path. For example,
if the script is named *production-inventory.py*, it resides in repos main
directory */home/user/playbooks/*, then it will assume that inventory data
resides in */home/user/playbooks/data/inventory/production-inventory.yml* file.

As mentioned earlier, the script also stores some configuration options:
* backend_domain - name of the default domain where all realative (not ending
with a '.') domains reside.
* ipaddress_keywords - the list of extra keyval variables (apart from
    "ansible_ssh_host") that should be treated as ip addresses. This is used
     mostly for user's input checking.
* ipnetwork_keywords - the list of keyval variables that should be treated as
     ip addresses. This is used mostly for user's input checking.

## Principle of operation

The script uses Ansibles dynamic inventory API:

http://docs.ansible.com/developing_inventory.html

The ansible itself calls the script passed on the command line (-i/--inventory-file),
and if it detects that it is an executable python script - it calls it with
"--list" parameter and excpets whole inventory in JSON format on stdout. The
format of the output is specified at the link above.

The script itself does some sanity checking on the inventory before returning it
to ansible:
* if manual changes were detected:
 * it recalculates the usage of all the ip pools
 * checks inexistant child groups and host group members
 * checks for overlapping ip pools
* it always checks if **all** the hosts have _ansible_ssh_host_ variable defined

## On disk configuration file format

All inventory files that can be found in data/inventory dir. The are YAML
documents in following format:

```
_meta:
  checksum: xxxx
  version: 1
ippools:
  ippool1:
    network: <network-1>
    allocated:
      - <ip11>
      - <ip12>
      - <ip13>
    reserved:
      - <ip14>
      - <ip15>
  ippool2:
    network: <network-2>
    allocated:
      - <ip21>
      - <ip22>
      - <ip23>
    reserved:
      - <ip24>
      - <ip25>
hosts:
  host1:
    aliases:
      - alias11
      - alias12
      - alias13
    keyvals:
      var11: val11
      var12: val12
      var13: val13
  host1:
    aliases:
      - alias21
      - alias22
      - alias23
    keyvals:
      var21: val21
      var22: val22
      var23: val23
  host3:
    aliases:
      - alias31
      - alias32
      - alias33
    keyvals:
      var31: val31
      var32: val32
      var33: val33
groups:
  group1:
    hosts:
      - host1
      - host2
      - host3
    children:
      - group2
    ippools:
      ansible_ssh_host: ippool1
      tunnel_ip: ippool2
  group2:
    hosts: []
    children: []
    ippools: {}
```

File may be edited by hand or using the script. Please notice that if manual
modification was detected, then the script will perform cleanup and verification
tasks mentioned in previous paragraph.

The meaning of fields is as follows:
* *_meta* - scripts internal data
 * *checksum* - the checksum of the inventory data. Used to detect manual changes
    to the file
 * *version* - in case the on-disk format changes, this field will help the script
    to identify which format inventory file uses.
* *ippools* - information about configured ip pools. Each entry is the name of
    particular ip pool
 * *network* - IPv4/6 network from which ip addresses will be assigned
 * *allocated* - list of IPs that has been already allocated in this pool
 * *reserved* - list of IPs that should not be allocated/reserved IPs
* *hosts* - information about hosts stored in the inventory. Each entry is the
    name of particular host
 * *aliases* - list of aliases assigned to the host. Each alias should be an fqdn
 * *keyvals* - this contains a dictionary with host variables that would normally
    be stored in host_vars/ directory
* *groups* - information about groups stored in the inventory. Each entry is the
    name of particular host.
 * *hosts* - list of hosts belonging to given group. Each entry must be on of
    the keys in *hosts* hashs
 * *children* - lists of child-groups assigned to this group. Each entry must
    be one of the keys in *groups* hash
 * *ippools* - each key is a keyval key user normally uses while setting host
    vars. If the value of the keyval, during assignement, is unspecified and is
    expected to be of ip address type, then the script usess the name of the
    ippool assigned here to identify ippool which should assign the address.

All domain names, unless explicitly marked as absolute with trailing dot, are
treated as relative to main domain: *backend_domain* variable defined in the
thin wrapper script.

## Common scenarios

Script source is well documented and the script itself provides built-in help:

```
$ ./hosts-production.py --help
usage: ./hosts-production.py [-h] [--version] [-v] [--initialize-inventory] [-s] [--list]
                  {ippool,group,host} ...

Dynamic inventory script for ./hosts-production.py.

positional arguments:
  {ippool,group,host}   subcommand groups
    ippool              IP address pools manipulation.
    group               Group membership manipulation.
    host                Host manipulation.

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Provide extra logging messages.
  --initialize-inventory
                        Start with empty inventory.
  -s, --std-err         Log to stderr instead of /dev/null
  --list                Dump all inventory data in JSON (used by Ansible
                        itself).

Author: Pawel Rozlach <pawel.rozlach@brainly.com>

```

Below, I will try to cover a setup of a new hypervisor hosts along with some
guests machines. It should give the reader a quick overview of the usage of the
script.

* Make sure our working directory is clean (no changes to the repo)
* Identify in which inventory the new hosts should reside

    ```
    ls -1l *.py
    -rwxrwxr-x. 1 vespian vespian 591 Nov 19 14:22 hosts-dev.py
    -rwxrwxr-x. 1 vespian vespian 591 Nov 19 14:21 hosts-production.py
    ```
These files relate directly to:

    ```
    ls -l data/inventory/*
    -rw-rw-r--. 1 vespian vespian 700 Nov 17 16:05 data/inventory/hosts-dev.yml
    -rw-rw-r--. 1 vespian vespian 700 Nov 17 16:05 data/inventory/hosts-production.yml

    ```
* We want to start with an empty inventory, so we issue the command with
  '-i/--initialize-inventory'

    ```
    ./hosts-production.py --initialize-inventory
    ```
* Lets first create some groups

    ```
    ./hosts-production.py group --group-name front --add
    ./hosts-production.py group --group-name guests-y1 --add
    ./hosts-production.py group --group-name hypervisor --add

    ```
* Now, we assign network 192.168.125.0/24 for guests on our hypervisor host. The
    gateway address must be .1, network and broadcast addresses will not be assigned
    by the tool by default.

    ```
    ./hosts-production.py ippool --ippool-name y1_guests --add 192.168.125.0/24 --book 192.168.125.1 --assign guests-y1 ansible_ssh_host
    ```
* Network 192.168.255.0/24 will be used for tunel addresses on our hypervisor hosts

    ```
    ./hosts-production.py ippool --ippool-name tunels --add 192.168.255.0/24 --assign hypervisor tunnel_ip
    ```
* Now, lets add some hosts:
    * for y1-front.foobar we want to set up an alias
    * for y1 public ip address/address used by ssh should be 1.2.3.4
    * y1-front.foobar and foobarator.y1 ip addresses should be autoassigned
    * for hypervisor host we want last octet of the tunnel address to match
    it's ippool (so no auto-assignement).
    * all the commands here can be broken into multiple smaller one with just
    one operation per *./hosts-production.py* execution. Here I want to should
    how to add it in more efficient way.

    ```
    ./hosts-production.py host --host-name y1-front.foobar --add --alias-add front-foobar.y1 --var-set ansible_ssh_host --group-add guests-y1 front
    ./hosts-production.py host --host-name foobarator.y1 --add --var-set ansible_ssh_host --group-add guests-y1
    ./hosts-production.py host --host-name y1 --add --var-set tunnel_ip:192.168.1.125 ansible_ssh_host:1.2.3.4 --group-add hypervisor

    ```
* Lets see how our inventory looks like now
 * first the groups:

    ```
    for i in `./hosts-production.py group --list-all | sort`; do echo "\#\#\#\# $i"; ./hosts-production.py group --show --group-name $i; done

    #### front
    Hosts:
        - y1-front.foobar
    Children:
        <None>
    Ip pools:
        <None>

    #### guests-y1
    Hosts:
        - foobarator.y1
        - y1-front.foobar
    Children:
        <None>
    Ip pools:
        ansible_ssh_host:y1_guests

    #### hypervisor
    Hosts:
        - y1
    Children:
        <None>
    Ip pools:
        tunnel_ip:tunels

    ```
 * now the hosts:

    ```
    for i in `./hosts-production.py host --list-all | sort`; do echo "\#\#\#\# $i"; ./hosts-production.py host --show --host-name $i; done

    #### foobarator.y1
    Aliases:
        <None>
    Host variables:
        ansible_ssh_host:192.168.125.3

    #### y1
    Aliases:
        <None>
    Host variables:
        tunnel_ip:192.168.1.125
        ansible_ssh_host:1.2.3.4

    #### y1-front.foobar
    Aliases:
        - front-foobar.y1
    Host variables:
        ansible_ssh_host:192.168.125.2

    ```
 * this is how inventory looks on disk:

    ```
    _meta:
    checksum: 6d8581df9e68154c7c7118a24ca8a391ad309a233654d044c5f920683cfc0c66
    version: 1
    groups:
    front:
        children: []
        hosts:
        - y1-front.foobar
        ippools: {}
    guests-y1:
        children: []
        hosts:
        - foobarator.y1
        - y1-front.foobar
        ippools:
        ansible_ssh_host: y1_guests
    hypervisor:
        children: []
        hosts:
        - y1
        ippools:
        tunnel_ip: tunels
    hosts:
    foobarator.y1:
        aliases: []
        keyvals:
        ansible_ssh_host: 192.168.125.3
    y1:
        aliases: []
        keyvals:
        ansible_ssh_host: 1.2.3.4
        tunnel_ip: 192.168.1.125
    y1-front.foobar:
        aliases:
        - front-foobar.y1
        keyvals:
        ansible_ssh_host: 192.168.125.2
    ippools:
    tunels:
        allocated: []
        network: 192.168.255.0/24
        reserved: []
    y1_guests:
        allocated:
        - 192.168.125.2
        - 192.168.125.3
        network: 192.168.125.0/24
        reserved:
        - 192.168.125.1
    ```
 * and what is going to be presented to ansible

    ```
    ./hosts-production.py --list

    {
        "_meta": {
            "hostvars": {
                "foobarator.y1": {
                    "aliases": [],
                    "ansible_ssh_host": "192.168.125.3"
                },
                "y1": {
                    "aliases": [],
                    "ansible_ssh_host": "1.2.3.4",
                    "tunnel_ip": "192.168.1.125"
                },
                "y1-front.foobar": {
                    "aliases": [
                        "front-foobar.y1"
                    ],
                    "ansible_ssh_host": "192.168.125.2"
                }
            }
        },
        "all": {
            "children": [],
            "hosts": [
                "y1",
                "foobarator.y1",
                "y1-front.foobar"
            ],
            "vars": {}
        },
        "front": {
            "children": [],
            "hosts": [
                "y1-front.foobar"
            ],
            "vars": {}
        },
        "guests-y1": {
            "children": [],
            "hosts": [
                "foobarator.y1",
                "y1-front.foobar"
            ],
            "vars": {}
        },
        "hypervisor": {
            "children": [],
            "hosts": [
                "y1"
            ],
            "vars": {}
        }
    }

    ```
  * and that's how ansible sees it

    ```
    ansible -i ./hosts-production.py --list-hosts all
        y1-front.foobar
        foobarator.y1
        y1

    ```

# Debugging, common problems:

* Script has some debug logging implemented, please check '-v/--verbose' and
    '--s/--stdout' options for more info:

    ```
    $ ./hosts-production.py -vs host -l                                                                                                                                                                                                                                   [17:36:49]
    __init__.py[24440] DEBUG: /home/foo/bar/playbooks/tools/__init__.py is starting, config: Namespace(add=False, del_alias=None, del_var=None, delete=False, host_name=None, initialize_inventory=False, list=False, list_all=True, set_alias=None, set_var=None, show=False, std_err=True, subcommand='host', verbose=True), inventory_path: /home/foo/bar/hosts-production.yml
    __init__.py[24440] DEBUG: Parsing ippools into objects
    __init__.py[24440] DEBUG: Parsing hosts into objects
    __init__.py[24440] DEBUG: Parsing groups into objects
    __init__.py[24440] DEBUG: Inventory /home/foo/bar/hosts-production.yml has been loaded.
    foobarator.y1
    y1
    y1-front.foobar
    ```

* In case if script stalls, it is strongly advised to check debugging output,
    because it may possible that script is re-checking the inventory due to
    checksum mismatch. This operation is CPU intensive, and should be optimized.
    This should be especially visible with large inventories.

* Editing inentory by hand is possible but not adviced - be warned. Additionally
   it will triger inventory recheck - please see earlier paragraph.

# Miscellaneus

* Hostvars with stricter type checking:
 * by default
  * ansible_ssh_port: int
  * ansible_ssh_host: ip_addr (mandatory)
  * ansible_ssh_user: str
  * ansible_connection: str
 * used for this exercise:
  * tunnel_ip: ip

## Author Information

This script has been created by Pawel Rozlach during his work for Brainly.com,
and then opensourced by the company on Apache 2.0 license. Please check the
![LICENSE](LICENSE) file for more details.
