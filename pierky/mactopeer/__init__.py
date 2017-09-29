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

import ipaddress
import json
import logging
import math
from six.moves import queue
from six.moves.urllib.request import urlopen
from six.moves.urllib.error import HTTPError
from six import u
import threading
import napalm_base

from .errors import DeviceConfigError


logger = logging.getLogger("mac-to-peer")


class MACToPeer(object):

    def validate_device(self, d):
        if "hostname" not in d:
            raise DeviceConfigError("Missing 'hostname'", d)
        if not d["hostname"].strip():
            raise DeviceConfigError("Empty value for 'hostname'", d)
        if "vendor" not in d:
            raise DeviceConfigError("Missing 'vendor'", d)
        if not d["vendor"].strip():
            raise DeviceConfigError("Empty value for 'vendor'", d)
        if not d.get("username", None) and not self.read_from_file:
            logger.warning("No username given for {}; "
                           "this can lead to authentication "
                           "problems if no other methods are "
                           "supported.".format(d["hostname"]))

    def __init__(self, devices, filters, output,
                 threads=4,
                 read_from_file=None, write_to_file=None):

        self.devices = devices
        self.filters = filters or ([], [], [])
        self.output = output

        self.threads = threads

        self.read_from_file = read_from_file
        self.write_to_file = write_to_file

        self.data = {}
        self.mac_peer_table = None

        for device in self.devices:
            self.validate_device(device)

    def get_data(self):
        if self.read_from_file:
            self.data = json.load(self.read_from_file)
        else:
            self._load_data_from_devices()

        self.mac_peer_table = self._get_mac_peer_table()

        self._enrich_via_peeringdb()

        return self.mac_peer_table

    def _write_output(self):
        raise NotImplementedError()

    def write_output(self):
        if not self.mac_peer_table:
            self.get_data()
        self._write_output()

    def _load_data_from_devices(self):
        if len(self.devices) == 1:
            device = self.devices[0]
            res = self._get_data_from_device(device)
            if res:
                self.data[device["hostname"]] = res
        else:
            tasks = queue.Queue()
            for device in self.devices:
                tasks.put(device)

            threads = []
            for i in range(self.threads):
                threads.append(
                    threading.Thread(target=self._process_queue,
                                     args=(tasks, self.data))
                )
            for thread in threads:
                thread.start()

            tasks.join()

            for thread in threads:
                thread.join()

        if self.write_to_file:
            json.dump(self.data, self.write_to_file)

    @staticmethod
    def _process_queue(q, data):
        while True:
            try:
                device = q.get(block=False)
            except queue.Empty:
                return

            res = MACToPeer._get_data_from_device(device)
            if res:
                data[device["hostname"]] = res
            q.task_done()

    @staticmethod
    def _get_data_from_device(device):
        try:
            driver = napalm_base.get_network_driver(device["vendor"])
        except napalm_base.exceptions.ModuleImportError as e:
            url = "https://napalm.readthedocs.io/en/latest/support/index.html"
            logger.error("Can't load the NAPALM driver for vendor '{}': {} - "
                         "Please be sure the vendor is one of those supported "
                         "by NAPALM (the 'vendor' argument must be filled "
                         "with a value taken from the 'Driver Name' row of "
                         "the table at this URL: {}).".format(
                            device["vendor"], str(e), url
                         ))
            return None

        connection = driver(
            hostname=device["hostname"],
            username=device.get("username", None),
            password=device.get("password", None),
            optional_args=device.get("optional_args", {})
        )

        hostname = device["hostname"]

        logger.info("Connecting to {}...".format(hostname))
        try:
            connection.open()
        except Exception as e:
            logger.error("Can't connect to {}: {}".format(
                hostname, str(e)))
            return None

        arp_table = []
        logger.info("Getting ARP table from {}...".format(hostname))
        try:
            arp_table = connection.get_arp_table()
        except Exception as e:
            logger.error("Can't get ARP table from {}: {}".format(
                hostname, str(e)))
            return None

        ipv6_neighbors_table = []
        if not device.get("arp_only", False):
            logger.info("Getting IPv6 neighbors table from {}...".format(
                hostname
            ))
            try:
                ipv6_neighbors_table = connection.get_ipv6_neighbors_table()
            except AttributeError as e:
                logger.warning("Skipping IPv6 neighbors table: "
                               "please consult the Caveats section of README")
            except Exception as e:
                logger.error("Can't get IPv6 neighbors table "
                             "from {}: {}".format(
                                hostname, str(e)))
                return None

        bgp_neighbors = {}
        logger.info("Getting BGP neighbors from {}...".format(hostname))
        try:
            bgp_neighbors = connection.get_bgp_neighbors()
        except Exception as e:
            logger.error("Can't get BGP neighbors from {}: {}".format(
                hostname, str(e)))
            return None

        logger.info("Disconnecting from {}...".format(hostname))
        try:
            connection.close()
        except Exception as e:
            logger.warning("Error while disconnecting from {}: {}".format(
                hostname, str(e)))

        # Normalize data
        arp_table = [{
            "interface": _["interface"],
            "ip": str(ipaddress.ip_address(_["ip"])),
            "mac": _["mac"].strip().lower()
        } for _ in arp_table]

        ipv6_neighbors_table = [{
            "interface": _["interface"],
            "ip": str(ipaddress.ip_address(_["ip"])),
            "mac": _["mac"].strip().lower()
        } for _ in ipv6_neighbors_table]

        peers = bgp_neighbors["global"]["peers"]
        bgp_neighbors = {
            "global": {
                "peers": {
                    _.lower(): {
                        "remote_as": peers[_]["remote_as"],
                        "description": peers[_]["description"]
                    } for _ in peers
                }
            }
        }

        return {
            "arp": arp_table,
            "ipv6_neighbors": ipv6_neighbors_table,
            "bgp_neighbors": bgp_neighbors
        }

    def _get_mac_peer_table_from_host(self, host):
        res = {}

        peers = host["bgp_neighbors"]["global"]["peers"]
        arp_table = host["arp"]
        ipv6_neighbors_table = host["ipv6_neighbors"]

        filter_mac, filter_ip, filter_asn = self.filters

        for lst in [arp_table, ipv6_neighbors_table]:
            for entry in lst:
                mac = entry["mac"]
                ip = entry["ip"]
                iface = entry["interface"]

                # MAC address filtered out?
                if mac.lower() in filter_mac:
                    continue

                # IP address filtered out?
                if filter_ip:
                    ip_obj = ipaddress.ip_address(u(ip))
                    filtered = False
                    for filtered_ip in filter_ip:
                        if ip_obj in filtered_ip:
                            filtered = True
                            break
                    if filtered:
                        continue

                # Add MAC address to the resultset
                if mac not in res:
                    res[mac] = {
                        "ip_addrs": [],
                        "ifaces": [],
                        "peer_asns": {
                        }
                    }

                if ip not in res[mac]["ip_addrs"]:
                    res[mac]["ip_addrs"].append(ip)

                if iface not in res[mac]["ifaces"]:
                    res[mac]["ifaces"].append(iface)

                # Is there a BGP neighbor for the IP address?
                if ip in peers:
                    asn = str(peers[ip]["remote_as"])
                    descr = peers[ip]["description"]

                    # ASN filtered out?
                    if asn in filter_asn:
                        continue

                    if asn not in res[mac]["peer_asns"]:
                        res[mac]["peer_asns"][asn] = {
                            "description": descr,
                            "ip_addrs": [ip]
                        }

                    if ip not in res[mac]["peer_asns"][asn]["ip_addrs"]:
                        res[mac]["peer_asns"][asn]["ip_addrs"].append(ip)

                if len(res[mac]["peer_asns"]) > 1:
                    logger.warning(
                        "MAC address {mac} used for "
                        "{cnt} different peers: {peers}".format(
                            mac=mac,
                            cnt=len(res[mac]["peer_asns"]),
                            peers=", ".join(res[mac]["peer_asns"])
                        )
                    )

        return res

    def _get_mac_peer_table(self):
        res = {}

        for hostname in self.data:
            res[hostname] = self._get_mac_peer_table_from_host(
                self.data[hostname]
            )

        return res

    def _enrich_via_peeringdb(self):

        def ip_is_global(ip_addr_obj):
            if hasattr(ip_addr_obj, "is_global"):
                return ip_addr_obj.is_global
            return not (
                ip_addr_obj.is_multicast or
                ip_addr_obj.is_private or
                ip_addr_obj.is_unspecified or
                ip_addr_obj.is_reserved or
                ip_addr_obj.is_loopback or
                ip_addr_obj.is_link_local
            )

        _, _, filter_asn = self.filters

        devices_with_pdb = [
            d["hostname"] for d in self.devices
            if d.get("use_peeringdb", False)
        ]
        if not devices_with_pdb:
            return

        # List of unique IP addresses that have not a BGP peer on the router.
        ip_addrs = {
            "4": [],
            "6": []
        }
        for hostname in self.mac_peer_table:
            if hostname not in devices_with_pdb:
                continue
            for mac in self.mac_peer_table[hostname]:
                entry = self.mac_peer_table[hostname][mac]
                if entry["ip_addrs"] and not entry["peer_asns"]:
                    for ip_addr in entry["ip_addrs"]:
                        ip_addr_obj = ipaddress.ip_address(
                            u(ip_addr)
                        )

                        if not ip_is_global(ip_addr_obj):
                            continue

                        ip_addr = str(ip_addr_obj)
                        if ip_addr not in ip_addrs[str(ip_addr_obj.version)]:
                            ip_addrs[str(ip_addr_obj.version)].append(ip_addr)

        # Chunks of max 20 IP addr per AFI that will be fetched from PeeringDB
        chunks = []
        for ip_ver in ["4", "6"]:
            chunk = []
            for ip_addr in ip_addrs[ip_ver]:
                chunk.append(ip_addr)
                if len(chunk) >= min(
                    math.ceil(len(ip_addrs[ip_ver]) / float(self.threads)),
                    20
                ):
                    chunks.append(chunk)
                    chunk = []
            if chunk:
                chunks.append(chunk)

        if not chunks:
            return

        # Threads to fetch data from PDB
        tasks = queue.Queue()
        for chunk in chunks:
            tasks.put(chunk)

        # asns_from_pdb will contain the result: [("ip_addr", "asn", "descr")]
        asns_from_pdb = []
        threads = []
        for i in range(self.threads):
            threads.append(
                threading.Thread(
                    target=self._fetch_asn_from_peeringdb,
                    args=(tasks, asns_from_pdb)
                )
            )

        logger.info("Fetching missing ASNs from PeeringDB...")
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # asns_from_pdb is ready
        for hostname in self.mac_peer_table:
            if hostname not in devices_with_pdb:
                continue
            for mac in self.mac_peer_table[hostname]:
                entry = self.mac_peer_table[hostname][mac]
                if entry["ip_addrs"] and not entry["peer_asns"]:
                    for ip_addr, asn, net_name in asns_from_pdb:
                        if asn in filter_asn:
                            continue
                        if ip_addr in entry["ip_addrs"]:
                            entry["peer_asns"][asn] = {
                                "description": net_name,
                                "ip_addrs": [ip_addr],
                                "from_peeringdb": True
                            }

    @staticmethod
    def _get_url(url):
        try:
            response = urlopen(url)
        except HTTPError as e:
            if e.code == 404:
                return
            else:
                logging.error(
                    "HTTP error while retrieving info from PeeringDB: "
                    "code: {}, reason: {} - {} [{}]".format(
                        e.code, e.reason, str(e), url
                    )
                )
                return
        except Exception as e:
            logging.error(
                "Error while retrieving info from PeeringDB: {}".format(
                    str(e)
                )
            )
            return

        raw = response.read().decode("utf-8")
        return json.loads(raw)

    @staticmethod
    def _download_from_peeringdb(ip_addrs):
        # Returns list of tuple ('ip_addr', 'ASN', 'net name')
        ip_addr_asn = []

        # Fetch NetIXLan objects from PeeringDB
        ip_field = "ipaddr{}".format("6" if ":" in ip_addrs[0] else "4")

        url = "https://www.peeringdb.com/api/netixlan?{}__in={}".format(
            ip_field, ",".join(ip_addrs)
        )

        netixlan_set = MACToPeer._get_url(url)
        if not netixlan_set:
            return
        if not netixlan_set["data"]:
            return

        # List of unique net objects that must be fetched from PeeringDB
        net_ids = []
        for netixlan in netixlan_set["data"]:
            net_id = str(netixlan["net_id"])
            if net_id not in net_ids:
                net_ids.append(net_id)

        # Fetch Net objects from PeeringDB
        url = "https://www.peeringdb.com/api/net?id__in={}".format(
            ",".join(net_ids)
        )

        net_set = MACToPeer._get_url(url)
        if not net_set:
            return

        # Dict: {'<net_id>': {'asn': '<ASN>', 'name': '<name>'}}
        net_id_asn = {}
        for net in net_set["data"]:
            net_id_asn[str(net["id"])] = {
                'asn': str(net["asn"]),
                'name': net["name"].strip()
            }

        # Results
        for netixlan in netixlan_set["data"]:
            net_id = str(netixlan["net_id"])
            if net_id in net_id_asn:
                ip_addr = netixlan[ip_field]
                ip_addr_asn.append(
                    (ip_addr,
                     net_id_asn[net_id]['asn'],
                     net_id_asn[net_id]['name'])
                )

        return ip_addr_asn

    @staticmethod
    def _fetch_asn_from_peeringdb(tasks, results):
        while True:
            try:
                ip_addrs = tasks.get(block=False)
            except queue.Empty:
                return

            pdb_info = MACToPeer._download_from_peeringdb(ip_addrs)
            if pdb_info:
                for ip_addr, asn, name in pdb_info:
                    results.append((ip_addr, asn, name))


class MACToPeer_JSON(MACToPeer):

    def _write_output(self):
        json.dump(self.mac_peer_table,
                  self.output, indent=2, sort_keys=True)


class MACToPeer_pmacct(MACToPeer):

    def _write_output(self):
        # Tuples (hostname, pmacct_ip).
        pmacct_info = []

        # Used just to format the lines that will form bgp_peer_src_as_map.
        max_pmacct_ip_len = 20
        for hostname in sorted(self.mac_peer_table):
            pmacct_ip = hostname
            for device in self.devices:
                if device["hostname"] == hostname:
                    pmacct_ip = device.get("pmacct_ip", hostname)
                    break
            if len(pmacct_ip) > max_pmacct_ip_len:
                max_pmacct_ip_len = len(pmacct_ip)

            pmacct_info.append((hostname, pmacct_ip))

        tpl = ("id={asn:10} "
               "ip={ip:" + str(max_pmacct_ip_len) + "} "
               "src_mac={mac}\n\n")

        for hostname, pmacct_ip in pmacct_info:
            self.output.write("! {}\n".format(hostname))
            for mac in sorted(self.mac_peer_table[hostname]):
                peer_asns = self.mac_peer_table[hostname][mac]["peer_asns"]
                if not peer_asns:
                    continue
                for asn in sorted(peer_asns):
                    self.output.write(
                        "! {ip} {name}{via_pdb}\n".format(
                            ip=", ".join(peer_asns[asn]["ip_addrs"]),
                            name=peer_asns[asn]["description"],
                            via_pdb=" (from PeeringDB)"
                                    if peer_asns[asn].get("from_peeringdb",
                                                          False)
                                    else ""
                        )
                    )
                    self.output.write(tpl.format(
                        asn=asn,
                        ip=pmacct_ip,
                        mac=mac
                    ))
