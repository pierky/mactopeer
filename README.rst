mac-to-peer
===========

|PYPI Version| |Python Versions|

Automatically fetch MAC/IP address tables (ARP and IPv6 neighbors) from devices and build MAC address to BGP peer ASN mappings.

Particularly focused on building **pmacct**'s *bgp_peer_src_as_map* `file <https://github.com/pmacct/pmacct/blob/master/examples/peers.map.example>`__.

.. code::

  router1#show ip arp
  Protocol  Address          Age (min)  Hardware Addr   Type   Interface
  Internet  192.0.2.1             101   0000.5E00.5300  ARPA   TenGigabitEthernet0/0/0
  
  router1#show bgp ipv4 unicast neighbors 192.0.2.1
  BGP neighbor is 192.0.2.1, remote AS 65536, internal link
  ...

Expected: **00:00:5E:00:53:00** -> **AS65536**

JSON output format:

.. code::

  $ mactopeer -u pierky -p - --hostname router1.example.com
  Enter password:
  {
    "router1.example.com": {
      "00:00:5E:00:53:00": {
        "ifaces": [
          "TenGigabitEthernet0/0/0"
        ],
        "ip_addrs": [
          "192.0.2.1"
        ],
        "peer_asns": {
          "65536": {
            "description": "my-peer",
            "ip_addrs": [
              "192.0.2.1"
            ]
          }
        }
      }
    }
  }

pmacct output format:

.. code::

  $ mactopeer -u pierky -p - --devices device.json -f pmacct
  Enter password:
  id=65536      ip=203.0.113.1          src_mac=00:00:5E:00:53:00

Installation and dependencies
-----------------------------

Install the program using pip:

.. code::

  pip install mactopeer

The script uses the `NAPALM <https://napalm.readthedocs.io/>`__ library to connect to network devices and to fetch data from them: you must install the whole library...

.. code::

  pip install napalm

... or at least the subset of network drivers needed to connect to the devices you actually need:

.. code::

  pip install napalm-ios napalm-junos

For more details, the full list of network drivers and their dependencies please see the official `NAPALM documentation <https://napalm.readthedocs.io/en/latest/installation/index.html>`__.

Usage and features
------------------

The ``--help`` shows all the options this program offers. See `its output in USAGE.rst <USAGE.rst>`__.

A list of devices can be provided using an input JSON file: for details about its schema please run ``mactopeer --help-devices``. See `its output in USAGE.rst <USAGE.rst#devices-json-file-schema>`__.

Filters can be set to skip entries on the basis of their MAC address, IP address or resulting peer ASN. Useful to exclude iBGP sessions or to handle exceptions.

Multithreading is also supported to fetch information from more than one device concurrently.

The list of supported devices can be found in the `Supported Devices <https://napalm.readthedocs.io/en/latest/support/index.html>`__ section of the NAPALM's documentation website. All those implementing the ``get_arp_table`` and ``get_bgp_neighbors`` methods should work: at time of writing they are EOS, IOS, IOSX-R, JunOS, NXOS, VyOS.

Integration with PeeringDB
++++++++++++++++++++++++++

The ``--use-peeringdb`` argument can be used to fetch missing peers' ASNs from PeeringDB, for example in case of multi-lateral peering (such as route servers at IXPs). In this case, routers have not a straight mapping between IP address and BGP neighborship, so the IP address is used to look into PeeringDB records to find the network which is using it.

Caveats
-------

- Currently VRF support is missing, mostly because it's not included in NAPALM yet.
- IPv6 neighbors table can only be fetched if a not yet released version of NAPALM is used, that is one which includes `this pull request <https://github.com/napalm-automation/napalm-base/pull/311>`__. To avoid the ``WARNING - Skipping IPv6 neighbors table`` message please use the ``--arp-only`` argument.

Author
------

Pier Carlo Chiodi - https://pierky.com/

Blog: https://blog.pierky.com/ Twitter: `@pierky <https://twitter.com/pierky>`_

.. |PYPI Version| image:: https://img.shields.io/pypi/v/mactopeer.svg
    :target: https://pypi.python.org/pypi/mactopeer/
.. |Python Versions| image:: https://img.shields.io/pypi/pyversions/mactopeer.svg
