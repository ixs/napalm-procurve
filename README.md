# napalm-procurve

[NAPALM](https://napalm-automation.net/) driver for HPE ProCurve networking
gear.

How to use
==========

Install napalm and install napalm-procurve via pip:
```
$ pip install napalm
$ pip install git+https://github.com/ixs/napalm-procurve.git
```

Test functionality:
```
#!/usr/bin/python
# Simple napalm-procurve test

import json
from napalm import get_network_driver

driver = get_network_driver('procurve')

switch = ('10.0.0.254', 22)
device = driver('10.0.0.254', 'user', 'password', optional_args={'ssh_config_file': '~/.ssh/config', 'port': 22})
device.open()

vals = device.get_mac_address_table()
device.close()
print json.dumps(vals, sort_keys=True,
                 indent=4, separators=(',', ': '))
```
