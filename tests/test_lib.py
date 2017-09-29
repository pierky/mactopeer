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
"""Core library"""

from ipaddress import IPv4Network, IPv6Network
import json
import logging
import os
import pytest
from six import StringIO

import napalm_base
import napalm_base.test.models as napalm_models

from pierky.mactopeer import MACToPeer, MACToPeer_JSON, MACToPeer_pmacct
from pierky.mactopeer.cli import build_filters_mac, build_filters_ip, \
                                 build_filters_asn
from pierky.mactopeer.errors import MACToPeerError

@pytest.mark.parametrize(
    "kwargs", [
        {
            "device": {},
            "fail": "Missing 'hostname'"
        }, {
            "device": {"hostname": ""},
            "fail": "Empty value for 'hostname'"
        }, {
            "device": {"hostname": "localhost"},
            "fail": "Missing 'vendor'"
        }, {
            "device": {"hostname": "localhost", "vendor": ""},
            "fail": "Empty value for 'vendor'"
        }, {
            "device": {"hostname": "localhost", "vendor": "ios"},
        }
    ]
)
def test_device_validation(kwargs):
    device = kwargs.get("device")
    fail = kwargs.get("fail", None)

    if not fail:
        devices = [device]
        lib = MACToPeer(devices, None, None)
    else:
        with pytest.raises(MACToPeerError, match=r".*" + fail + ".*"):
            devices = [device]
            lib = MACToPeer(devices, None, None)
        return

def test_napalm_model_arp_table():
    assert hasattr(napalm_models, "arp_table")
    for k in ["interface", "mac", "ip"]:
        assert k in napalm_models.arp_table

def test_napalm_model_ipv6_neighbor():
    try:
        assert hasattr(napalm_models, "ipv6_neighbor")
    except:
        pytest.skip("ipv6_neighbor not implemented in NAPALM")
    for k in ["interface", "mac", "ip"]:
        assert k in napalm_models.ipv6_neighbor

def test_napalm_model_get_bgp_neighbors():
    for k in ["remote_as", "description"]:
        assert k in napalm_models.peer

def test_missing_napalm_module(caplog):
    device = {"hostname": "192.0.2.1", "vendor": "ACME_ROUTERS"}
    devices = [device]

    lib = MACToPeer(devices, None, None)
    res = lib.get_data()
    assert "Can't load the NAPALM driver for vendor" in caplog.text
    assert res == {}

@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "scenario": "simple",
            "devices_cnt": 1
        }, {
            "scenario": "3_devices",
            "devices_cnt": 3
        }, {
            "scenario": "3_devices",
            "devices_cnt": 3,
            "filters": (build_filters_mac("22:22:22:aa:bb:cc"), [], []),
            "exp_res_tag": "mac_filter"
        }, {
            "scenario": "3_devices",
            "devices_cnt": 3,
            "filters": ([], build_filters_ip("192.0.2.3"), []),
            "exp_res_tag": "ip_filter"
        }, {
            "scenario": "3_devices",
            "devices_cnt": 3,
            "filters": ([], [], build_filters_asn("1")),
            "exp_res_tag": "asn_filter"
        }, {
            "scenario": "3_devices",
            "devices_cnt": 3,
            "filters": ([], build_filters_ip("192.0.2.2/31"), []),
            "exp_res_tag": "prefix_filter"
        }, {
            "scenario": "more_mac",
            "devices_cnt": 1
        }, {
            "scenario": "same_mac_more_peers",
            "devices_cnt": 1
        }, {
            "scenario": "same_mac_more_peers_diff_asn",
            "devices_cnt": 1,
            "log": ["used for 2 different peers"]
        }, {
            "scenario": "pdb_live",
            "devices_cnt": 1,
            "use_peeringdb": True
        }
    ],
    ids=[
        "simple",
        "3_devices",
        "3_devices_mac_filter",
        "3_devices_ip_filter",
        "3_devices_asn_filter",
        "3_devices_prefix_filter",
        "more_mac",
        "same_mac_more_peers",
        "same_mac_more_peers_diff_asn",
        "peeringdb_live"
    ]
)
@pytest.mark.parametrize("fmt", ["json", "pmacct"])
def test_core_library(monkeypatch, caplog, kwargs, fmt):
    scenario = kwargs.get("scenario")
    devices_cnt = kwargs.get("devices_cnt")
    filters = kwargs.get("filters", ([], [], []))
    exp_res_tag = kwargs.get("exp_res_tag", None)
    log = kwargs.get("log", None)
    use_peeringdb = kwargs.get("use_peeringdb", None)

    def fake_get_network_driver(*args, **kwargs):
        return napalm_base.MockDriver

    monkeypatch.setattr(napalm_base, "get_network_driver",
                        fake_get_network_driver)

    if not log:
        caplog.set_level(logging.ERROR)
    else:
        caplog.set_level(logging.INFO)

    dir_path = os.path.join(os.path.dirname(__file__), "mocked_data", scenario)

    devices = []
    device_idx = 0
    for i in range(devices_cnt):
        device_idx += 1
        device = {"hostname": "router{}".format(device_idx),
                  "vendor": "ios",
                  "optional_args": {
                      "path": os.path.join(dir_path, "router{}".format(device_idx))
                  }}
        if use_peeringdb is not None:
            device["use_peeringdb"] = use_peeringdb
        devices.append(device)

    lib_class = MACToPeer_JSON if fmt == "json" else MACToPeer_pmacct

    out_file = StringIO()
    lib = lib_class(devices, filters, out_file, threads=2)
    lib.write_output()
    out_file.seek(0)
    res = out_file.getvalue()

    expected_results_file = "expected_results"
    if exp_res_tag:
        expected_results_file += "." + exp_res_tag
    expected_results_file += "." + fmt

    exp_res = ""
    try:
        with open(os.path.join(dir_path, expected_results_file), "r") as f:
            exp_res = f.read()
    except:
        with open(os.path.join(dir_path, expected_results_file + ".from_test"), "w") as f:
            f.write(res)

    if not log:
        assert not caplog.records
    else:
        for log_msg in log:
            assert log_msg in caplog.text

    if fmt == "json":
        res = json.loads(res)
        exp_res = json.loads(exp_res)

    assert res == exp_res
