# Copyright (C) 2017 Pier Carlo Chiodi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import getpass
import ipaddress
import json
import os
import re
import six
import sys

from .errors import CLIParsingError
from .version import __version__, COPYRIGHT_YEAR


def make_parser():
    parser = argparse.ArgumentParser(
        description="mac-to-peer v{}: a tool to automatically "
                    "build a list of BGP neighbors starting from "
                    "the MAC address of their peers.".format(
                        __version__
                    ),
        epilog="Copyright (c) {} - Pier Carlo Chiodi - "
               "https://pierky.com".format(COPYRIGHT_YEAR)
    )
    parser.add_argument(
        "--help-devices",
        help="show details about the format of the JSON file "
             "that must be used to build the --devices file.",
        action="store_true"
    )

    group = parser.add_argument_group(
        title="Device(s) to get the data from",
        description="To use a list of devices the --devices "
                    "argument must be used; a single device can "
                    "be given using the --hostname argument."
    )
    group.add_argument(
        "--devices",
        help="path to the JSON file that contains the list of "
             "devices from which to get the data. Use '-' to "
             "read from stdin. "
             "Use the --help-devices argument to show details "
             "about the format of that JSON file.",
        type=argparse.FileType("r")
    )
    group.add_argument(
        "--hostname",
        help="IP address or hostname of the device from which "
             "to get the data."
    )
    group = parser.add_argument_group(
        title="Device(s) authentication and connection info",
        description="The following arguments, when provided, overried "
                    "those reported within the JSON file given in "
                    "the --devices argument."
    )
    group.add_argument(
        "-u", "--username",
        help="username for authenticating to the device(s)."
    )
    group.add_argument(
        "-p", "--password",
        help="password for authenticating to the device(s). "
             "Use '-' in order to be prompted."
    )
    group.add_argument(
        "-v", "--vendor",
        help="name of the NAPALM driver that must be used to connect to "
             "the device. It is mandatory if --hostname is used. "
             "It must be one of the values from the "
             "'Driver name' row of the following table: "
             "http://napalm.readthedocs.io/en/latest/support/index.html"
             "#general-support-matrix"
    )
    group.add_argument(
        "--arp-only",
        help="when set, it prevents the program from fetching IPv6 neighbors "
             "from the device(s).",
        action="store_true"
    )
    group.add_argument(
        "--optional-args",
        help="list of comma separated key=value pairs passed to "
             "Napalm drivers. For the list of supported optional "
             "arguments see this URL: "
             "http://napalm.readthedocs.io/en/latest/support/index.html#"
             "optional-arguments"
    )
    group.add_argument(
        "--use-peeringdb",
        action="store_true",
        help="use PeeringDB to obtain the ASN of those entries which "
             "have not a straight BGP session on the router (for "
             "example multi-lateral peering sessions at IXs via "
             "route server)."
    )

    group = parser.add_argument_group(
        title="Output options"
    )
    group.add_argument(
        "-o", "--output",
        type=argparse.FileType("w"),
        help="output file. Default: stdout.",
        default=sys.stdout,
        dest="output_file"
    )
    group.add_argument(
        "-f", "--format",
        choices=["json", "pmacct"],
        help="output format. When 'pmacct' is used, the output "
             "is built using the format of pmacct's bgp_peer_src_as_map "
             "(https://github.com/pmacct/pmacct/blob/"
             "c9d6b210210bc3232d6c31683103963ab2b15953/QUICKSTART#L1120 "
             "and also "
             "https://github.com/pmacct/pmacct/blob/master/examples/"
             "peers.map.example). Default: %(default)s.",
        default="json"
    )

    group = parser.add_argument_group(
        title="Filters",
        description="The following arguments can be used to filter out "
                    "entries on the basis of their MAC address, IP address "
                    "or peer ASN. Each argument can be set with a "
                    "comma-separated list of values (ex. --ignore-ip "
                    "192.168.0.1,10.0.0.1) or with the path to a file "
                    "containing one value on each line."
    )
    group.add_argument(
        "--ignore-mac",
        help="list of MAC addresses that will be ignored.",
        metavar="LIST_OR_FILE"
    )
    group.add_argument(
        "--ignore-ip",
        help="list of IP addresses or prefixes that will be ignored.",
        metavar="LIST_OR_FILE"
    )
    group.add_argument(
        "--ignore-asn",
        help="list of ASNs that will be ignored.",
        metavar="LIST_OR_FILE"
    )

    group = parser.add_argument_group(
        title="Misc options"
    )
    group.add_argument(
        "--threads",
        type=int,
        help="number of threads that will be used to fetch info "
             "from devices. Default: %(default)s.",
        default=4
    )
    group.add_argument(
        "--write-to-cache",
        type=argparse.FileType("w"),
        help="if provided, data fetched from devices are saved "
             "into this file for later use via the --read-from-cache "
             "argument.",
        metavar="CACHE_FILE"
    )
    group.add_argument(
        "--read-from-cache",
        type=argparse.FileType("r"),
        help="if provided, data are not fetched from devices but "
             "read from the CACHE_FILE file.",
        metavar="CACHE_FILE"
    )

    return parser


def get_optional_args(s):
    return {x.split('=')[0]: x.split('=')[1]
            for x in s.split(',')}


def build_devices(args):
    if not args.devices and not args.hostname:
        raise CLIParsingError(
            "One of the arguments --devices --hostname is required"
        )

    devices = []
    if args.devices:
        try:
            devices = json.load(args.devices)
        except Exception as e:
            raise CLIParsingError(
                "Can't parse the JSON file "
                "given in --devices: {}".format(str(e))
            )
    else:
        if not args.vendor:
            raise CLIParsingError(
                "--vendor is mandatory when --hostname is used."
            )

        devices.append({
            "hostname": args.hostname,
            "username": None,
            "password": None,
            "vendor": None,
            "arp_only": False,
            "optional_args": {},
            "use_peeringdb": False
        })

    password = None
    if args.password:
        if args.password == '-' and not args.read_from_cache:
            password = getpass.getpass('Enter password: ')
        else:
            password = args.password

    unique_hostname = []
    for device in devices:
        if args.username:
            device["username"] = args.username
        if password:
            device["password"] = password
        if args.vendor:
            device["vendor"] = args.vendor
        if args.arp_only:
            device["arp_only"] = True
        if args.use_peeringdb:
            device["use_peeringdb"] = True
        if args.optional_args:
            device["optional_args"] = get_optional_args(args.optional_args)

        hostname = device.get("hostname", "")
        if hostname in unique_hostname:
            raise CLIParsingError(
                "Duplicate devices: '{}'".format(device["hostname"])
            )

        unique_hostname.append(hostname)

    return devices


def build_filter(list_or_file):
    if not list_or_file:
        return []
    if os.path.exists(os.path.expanduser(list_or_file)):
        with open(list_or_file, "r") as f:
            return [_.lower() for _ in f.read().split("\n") if _.strip()]
    return [_.lower() for _ in list_or_file.split(",")]


def build_filters_mac(v):
    try:
        mac_lst = build_filter(v)
        for mac in mac_lst:
            if not re.match("^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$", mac):
                raise ValueError("invalid MAC address: {}".format(mac))
    except Exception as e:
        raise CLIParsingError(
            "Invalid MAC filter: {}".format(str(e))
        )
    return mac_lst


def build_filters_ip(v):
    ip_lst = []
    try:
        raw_ip_addrs = build_filter(v)
        for raw_ip_addr in raw_ip_addrs:
            ip_lst.append(ipaddress.ip_network(six.u(raw_ip_addr)))
    except Exception as e:
        raise CLIParsingError(
            "Invalid IP filter: {}".format(str(e))
        )
    return ip_lst


def build_filters_asn(v):
    try:
        asn_lst = build_filter(v)
        for asn in asn_lst:
            if not asn.isdigit():
                raise ValueError("invalid ASN: {}".format(asn))
    except Exception as e:
        raise CLIParsingError(
            "Invalid ASN filter: {}".format(str(e))
        )
    return asn_lst


def build_filters(args):
    mac_lst = build_filters_mac(args.ignore_mac)
    ip_lst = build_filters_ip(args.ignore_ip)
    asn_lst = build_filters_asn(args.ignore_asn)

    return mac_lst, ip_lst, asn_lst
