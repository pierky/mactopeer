Usage
-----

.. code::

  usage: mactopeer [-h] [--help-devices] [--devices DEVICES]
                   [--hostname HOSTNAME] [-u USERNAME] [-p PASSWORD] [-v VENDOR]
                   [--arp-only] [--optional-args OPTIONAL_ARGS]
                   [--use-peeringdb] [-o OUTPUT_FILE] [-f {json,pmacct}]
                   [--ignore-mac LIST_OR_FILE] [--ignore-ip LIST_OR_FILE]
                   [--ignore-asn LIST_OR_FILE] [--threads THREADS]
                   [--write-to-cache CACHE_FILE] [--read-from-cache CACHE_FILE]
  
  mac-to-peer v0.3.0: a tool to automatically build a list of BGP neighbors
  starting from the MAC address of their peers.
  
  optional arguments:
    -h, --help            show this help message and exit
    --help-devices        show details about the format of the JSON file that
                          must be used to build the --devices file.
  
  Device(s) to get the data from:
    To use a list of devices the --devices argument must be used; a single
    device can be given using the --hostname argument.
  
    --devices DEVICES     path to the JSON file that contains the list of
                          devices from which to get the data. Use '-' to read
                          from stdin. Use the --help-devices argument to show
                          details about the format of that JSON file.
    --hostname HOSTNAME   IP address or hostname of the device from which to get
                          the data.
  
  Device(s) authentication and connection info:
    The following arguments, when provided, overried those reported within the
    JSON file given in the --devices argument.
  
    -u USERNAME, --username USERNAME
                          username for authenticating to the device(s).
    -p PASSWORD, --password PASSWORD
                          password for authenticating to the device(s). Use '-'
                          in order to be prompted.
    -v VENDOR, --vendor VENDOR
                          name of the NAPALM driver that must be used to connect
                          to the device. It is mandatory if --hostname is used.
                          It must be one of the values from the 'Driver name'
                          row of the following table: http://napalm.readthedocs.
                          io/en/latest/support/index.html#general-support-matrix
    --arp-only            when set, it prevents the program from fetching IPv6
                          neighbors from the device(s).
    --optional-args OPTIONAL_ARGS
                          list of comma separated key=value pairs passed to
                          Napalm drivers. For the list of supported optional
                          arguments see this URL: http://napalm.readthedocs.io/e
                          n/latest/support/index.html#optional-arguments
    --use-peeringdb       use PeeringDB to obtain the ASN of those entries which
                          have not a straight BGP session on the router (for
                          example multi-lateral peering sessions at IXs via
                          route server).
  
  Output options:
    -o OUTPUT_FILE, --output OUTPUT_FILE
                          output file. Default: stdout.
    -f {json,pmacct}, --format {json,pmacct}
                          output format. When 'pmacct' is used, the output is
                          built using the format of pmacct's bgp_peer_src_as_map
                          (https://github.com/pmacct/pmacct/blob/c9d6b210210bc32
                          32d6c31683103963ab2b15953/QUICKSTART#L1120 and also ht
                          tps://github.com/pmacct/pmacct/blob/master/examples/pe
                          ers.map.example). Default: json.
  
  Filters:
    The following arguments can be used to filter out entries on the basis of
    their MAC address, IP address or peer ASN. Each argument can be set with a
    comma-separated list of values (ex. --ignore-ip 192.168.0.1,10.0.0.1) or
    with the path to a file containing one value on each line.
  
    --ignore-mac LIST_OR_FILE
                          list of MAC addresses that will be ignored.
    --ignore-ip LIST_OR_FILE
                          list of IP addresses or prefixes that will be ignored.
    --ignore-asn LIST_OR_FILE
                          list of ASNs that will be ignored.
  
  Misc options:
    --threads THREADS     number of threads that will be used to fetch info from
                          devices. Default: 4.
    --write-to-cache CACHE_FILE
                          if provided, data fetched from devices are saved into
                          this file for later use via the --read-from-cache
                          argument.
    --read-from-cache CACHE_FILE
                          if provided, data are not fetched from devices but
                          read from the CACHE_FILE file.
  
  Copyright (c) 2017 - Pier Carlo Chiodi - https://pierky.com


Devices JSON file schema
------------------------

.. code::

  
  The JSON file provided via the --devices argument must contain the list of
  devices which data will be fetched from.
  It must respect the following schema:
  [
    {
      "hostname": "IP address or hostname",
      "vendor": "see below",
      "username": "username",
      "password": "password",
      "arp_only": true|false,
      "use_peeringdb": true|false,
      "optional_args": {
        "arg1_name": "arg1_value",
        "arg2_name": "arg2_value",
        ...
      }
      "pmacct_ip": "IP address
    }, {
      <same as above>
    }
  ]
  
  Only "hostname" and "vendor" are mandatory.
  
  - "hostname" is the IP address or hostname used to connect to the device.
  
  - "vendor" is the name of the driver used by NAPALM to identify the type of 
  device: it must be one of the values reported in the "Driver name" row of this
  table:
  http://napalm.readthedocs.io/en/latest/support/index.html
  
  - "username" and "password" are used to authenticating to the device. The
  password can be omitted and provided via CLI by running the program with the
  "--password -" argument.
  
  - "arp_only" (default: false), if set, prevents the program from fetching IPv6
  neighbors table from the devices.
  
  - "use_peeringdb" (default: false), if set to True, allows the program to
  fetch from PeeringDB ASNs of IP addresses that have not a straight BGP
  neighborship on the router, for example in case of multi-lateral peering via
  route servers at an IXP.
  
  - "optional_args" can be used to pass additional arguments to the NAPALM
  driver used to connect to the device. A list of available arguments can be
  found here:
  http://napalm.readthedocs.io/en/latest/support/index.html#optional-arguments
  
  - "pmacct_ip" (default: same as "hostname") is only used when the output
  format is set to "pmacct" ("--format pmacct" argument); its value is used to
  fill the "ip" field of pmacct's "bgp_peer_src_as_map" and it can be used to
  provide an IP address different from the one given in "hostname".
  
