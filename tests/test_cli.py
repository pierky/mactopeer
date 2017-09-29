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
"""Devices and filters"""

import argparse
import getpass
from ipaddress import IPv4Network, IPv6Network
import json
import logging
import os
import pytest

from pierky.mactopeer import MACToPeer
from pierky.mactopeer.cli import make_parser, build_devices, build_filters
from pierky.mactopeer.errors import MACToPeerError

@pytest.mark.parametrize(
    "kwargs", [
        {
            "filename": "working1.json",
            "expected_results_filename": "working1.expected.json",
            "log": ["No username given for 192.168.0.1",
                    "No username given for router1.example.com"]
        }, {
            "filename": "working1.json",
            "cli": "-p -",
            "expected_results_filename": "working1.expected_with_pass.json",
            "log": ["No username given for 192.168.0.1",
                    "No username given for router1.example.com"]
        }, {
            "filename": "working1.json",
            "cli": "-p - -u testuser",
            "expected_results_filename": "working1.expected_with_pass_and_user.json"
        }, {
            "filename": "working1.json",
            "cli": "-p - -u testuser "
                   "--optional-args transport=telnet,port=23",
            "expected_results_filename": "working1.expected_with_optargs.json"
        }, {
            "cli": "--hostname router1.example.com",
            "fail": "--vendor is mandatory when --hostname is used"
        }, {
            "filename": "duplicate.json",
            "fail": "Duplicate devices"
        }, {
            "filename": "missing_hostname.json",
            "fail": "Missing 'hostname'"
        }, {
            "filename": "missing_vendor.json",
            "fail": "Missing 'vendor'"
        }, {
            "fail": "One of the arguments --devices --hostname is required"
        }, {
            "filename": "bad.json",
            "fail": "Can't parse the JSON file"
        }, {
            "cli": "--hostname router1.example.com --vendor ios",
            "expected_results_filename": "from_cli.expected.json",
            "log": ["No username given for router1.example.com"]
        }, {
            "cli": "--hostname router1.example.com --vendor ios "
                   "-p pass_from_cli -u testuser --arp-only --use-peeringdb",
            "expected_results_filename": "expected/from_cli.expected_with_args_from_cli.json"
        }
    ], ids=[
        "working",
        "working with pass from CLI",
        "working with user and pass from CLI",
        "working with opt args",
        "--vendor mandatory when --hostname is used",
        "duplicate devices",
        "missing hostname",
        "missing vendor",
        "no --devices nor --hostname",
        "bad JSON file",
        "device from CLI",
        "device from CLI with args"
    ]
)
def test_devices(monkeypatch, caplog, kwargs):
    filename = kwargs.get("filename", None)
    cli = kwargs.get("cli", "")
    expected_results_filename = kwargs.get("expected_results_filename", None)
    log = kwargs.get("log", None)
    fail = kwargs.get("fail", None)

    dir_path = os.path.join(os.path.dirname(__file__), "devices")

    def fake_getpass(*args, **kwargs):
        return "password from cli"

    monkeypatch.setattr(getpass, "getpass", fake_getpass)

    caplog.set_level(logging.INFO)

    devices = None
    if filename:
        file_path = os.path.join(dir_path, filename)
        devices = "--devices {}".format(file_path)

    parser = make_parser()
    args = parser.parse_args(
        "{devices} {cli}".format(
            devices=devices if devices else "", cli=cli
        ).split()
    )
    if not fail:
        devices = build_devices(args)
        lib = MACToPeer(devices, None, None)
    else:
        with pytest.raises(MACToPeerError, match=r".*" + fail + ".*"):
            devices = build_devices(args)
            lib = MACToPeer(devices, None, None)
        return

    if log:
        for msg in log:
            assert msg in caplog.text
    else:
        assert not caplog.records

    if expected_results_filename:
        expected_results_file_path = os.path.join(
            dir_path, "expected", expected_results_filename
        )
        if os.path.exists(expected_results_file_path):
            with open(expected_results_file_path, "r") as f:
                expected_results = json.load(f)
            assert devices == expected_results

@pytest.mark.parametrize(
    "kwargs", [
        {
            "cli": "--ignore-mac 11:22:33:44:55:66",
            "expected_results": (["11:22:33:44:55:66"], [], [])
        }, {
            "cli": "--ignore-mac 1122.3344.5566",
            "fail": "Invalid MAC filter"
        }, {
            "cli": "--ignore-mac 11:22:33:44:55:66,A1:A2:a3:a4:a5:a6",
            "expected_results": (["11:22:33:44:55:66", "a1:a2:a3:a4:a5:a6"],
                                 [], [])
        }, {
            "cli": "--ignore-mac 11:22:33:44:55:66,A1:A2:a3:a4:a5:a6 "
                   "--ignore-ip 192.0.2.1",
            "expected_results": (["11:22:33:44:55:66", "a1:a2:a3:a4:a5:a6"],
                                 [IPv4Network(u"192.0.2.1/32")], [])
        }, {
            "cli": "--ignore-mac 11:22:33:44:55:66,A1:A2:a3:a4:a5:a6 "
                   "--ignore-ip 192.0.2.1,192.0.2.1/24",
            "fail": "Invalid IP filter"
        }, {
            "cli": "--ignore-ip 192.0.2.1,192.0.2.0/24",
            "expected_results": ([],
                                 [IPv4Network(u"192.0.2.1/32"),
                                  IPv4Network(u"192.0.2.0/24")], []),
        }, {
            "cli": "--ignore-asn invalid_asn",
            "fail": "Invalid ASN filter"
        }, {
            "cli": "--ignore-asn 65535",
            "expected_results": ([], [], ["65535"])
        }, {
            "cli": "--ignore-mac tests/filters/mac",
            "expected_results": (["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"],
                                 [], [])
        }
    ], ids=[
        "1 mac",
        "1 invalid mac",
        "2 mac",
        "2 mac, 1 ip",
        "2 mac, 1 ip, 1 invalid prefix",
        "1 ip, 1 prefix",
        "1 invalid asn",
        "1 asn",
        "mac from file",
    ]
)
def test_filters(kwargs):
    cli = kwargs.get("cli")
    expected_results = kwargs.get("expected_results", None)
    fail = kwargs.get("fail", None)

    dir_path = os.path.join(os.path.dirname(__file__), "filters")

    parser = make_parser()
    args = parser.parse_args(
        "--hostname 192.0.2.1 -u testuser -p testpass --vendor ios {}".format(
            cli
        ).split()
    )

    if not fail:
        filters = build_filters(args)
    else:
        with pytest.raises(MACToPeerError, match=r".*" + fail + ".*"):
            filters = build_filters(args)
        return

    if expected_results:
        assert filters == expected_results
