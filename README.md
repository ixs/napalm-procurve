# napalm-procurve

[NAPALM](https://napalm-automation.net/) driver for HPE ProCurve networking
gear.

Supported devices
=================

All ProCurve OS devices should be supported. The code has been written and tested
having access to ProCurve 2848 and to E2910al-48G-PoE devices.

If a different device or a different firmware release should cause problems, please
open a GitHub issue and paste the appropriate output from the switch.

Development status
==================

The driver is functional and can be used to poll status information:

 * get_facts(): Return general device information
 * get_lldp_neighbors(): Fetch LLDP neighbor information
 * get_lldp_neighbors_detail(): Fetch LLDP details
 * get_environment(): CPU and Sensor details
 * get_config(): Read config
 * ping(): Ping remote ip
 * get_ntp_servers(): Return configured NTP servers
 * get_arp_table(): Get device ARP table
 * get_mac_address_table(): Get mac table of connected devices
 * get_interfaces(): Get interface status
 * get_interfaces_counters(): Get interface counters

Configuration changes are currently not supported, as the ProCurve OS does
not support an API to do changes in a decent way.
Incremental changes might be possible, but are difficult to implement.
Complete configuration uploads via sftp might be an option but have the
drawback that they cause an immediate reboot of the ProCurve device.

Maybe a later version will support configuration handling.

How to use
==========

Install napalm and install napalm-procurve via pip:
```
$ pip install napalm napalm-procurve
```

In case the latest development checkout is needed:
```
$ pip install git+https://github.com/ixs/napalm-procurve.git
```

Test functionality:
```
#!/usr/bin/python3
# Simple napalm-procurve test

import json
from napalm import get_network_driver

driver = get_network_driver('procurve')

switch = ('10.0.0.254', 22)
device = driver('10.0.0.254', 'manager', 'secret', optional_args={'ssh_config_file': '~/.ssh/config', 'port': 22})
device.open()

vals = device.get_mac_address_table()
device.close()
print json.dumps(vals, sort_keys=True,
                 indent=4, separators=(',', ': '))
```

License
=======

ASL2.0
