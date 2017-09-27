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

import getpass
import ipaddress
import json
import os

from .errors import CLIParsingError

def get_optional_args(s):
    return {x.split('=')[0]: x.split('=')[1]
            for x in s.split(',')}

def build_devices(args):
    if not args.devices and not args.hostname:
        raise CLIParsingError(
            "ERROR: one of the arguments --devices --hostname is required"
        )

    devices = []
    if args.devices:
        try:
            devices = json.load(args.devices)
        except Exception as e:
            raise CLIParsingError(
                "ERROR: can't parse the JSON file "
                "given in --devices: {}".format(str(e))
            )
    else:
        if not args.vendor:
            raise CLIParsingError(
                "ERROR: --vendor is mandatory when --hostname is used."
            )

        devices.append({
            "hostname": args.hostname,
            "username": None,
            "password": None,
            "vendor": None,
            "arp_only": False,
            "optional_args": {}
        })

    password = None
    if args.password:
        if args.password == '-' and not args.read_from_cache:
            try:
                password = getpass.getpass('Enter password: ')
            except KeyboardInterrupt:
                raise CLIParsingError("Aborted!")
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
        if args.optional_args:
            device["optional_args"] = get_optional_args(args.optional_args)

        if device["hostname"] in unique_hostname:
            raise CLIParsingError(
                "ERROR: duplicate devices: '{}'".format(device["hostname"])
            )

        unique_hostname.append(device["hostname"])

    return devices

def build_filter(list_or_file):
    if os.path.exists(os.path.expanduser(list_or_file)):
        with open(list_or_file, "r") as f:
            return [_.lower() for _ in f.read().split("\n")]
    return [_.lower() for _ in list_or_file.split(",")]

def build_filters(args):
    mac = []
    ip = []
    asn = []
    if args.ignore_mac:
        mac = build_filter(args.ignore_mac)
    if args.ignore_ip:
        raw_ip_addrs = build_filter(args.ignore_ip)
        for raw_ip_addr in raw_ip_addrs:
            ip.append(ipaddress.ip_network(raw_ip_addr.decode("utf-8")))
    if args.ignore_asn:
        asn = build_filter(args.ignore_asn)

    return mac, ip, asn
