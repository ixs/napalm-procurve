# Copyright 2017-2019 Andreas Thienemann. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""
Napalm driver for HP ProCurve devices

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import print_function
from __future__ import unicode_literals

import re
import sys
import socket
import telnetlib

from netmiko import ConnectHandler
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    CommandErrorException,
    ConnectionClosedException,
    ConnectionException,
)

from napalm.base.utils import py23_compat
import napalm.base.constants as C
import napalm.base.helpers


class ProcurveDriver(NetworkDriver):
    """Napalm driver for ProCurve."""

    def __init__(self,
                 hostname,
                 username,
                 password,
                 timeout=60,
                 optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}
        self.transport = optional_args.get('transport', 'ssh')
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'secret': '',
            'verbose': False,
            'keepalive': 30,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for k, v in netmiko_argument_map.items():
            try:
                self.netmiko_optional_args[k] = optional_args[k]
            except KeyError:
                pass
        self.global_delay_factor = optional_args.get('global_delay_factor', 1)
        self.port = optional_args.get('port', 22)

        self.device = None
        self.config_replace = False
        self.interface_map = {}

        self.profile = ["procurve"]

    def open(self):
        """Open a connection to the device."""
        device_type = 'hp_procurve_ssh'
        if self.transport == 'telnet':
            device_type = 'hp_procurve_telnet'
        self.device = ConnectHandler(
            device_type=device_type,
            host=self.hostname,
            username=self.username,
            password=self.password,
            **self.netmiko_optional_args)
        # ensure in enable mode
        self.device.enable()

    def close(self):
        """Close the connection to the device."""
        self.device.disconnect()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "Invalid input: " not in output:
                        break
            else:
                output = self.device.send_command(command)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def is_alive(self):
        """ Returns a flag with the state of the connection."""
        if self.device is None:
            return {'is_alive': False}
        try:
            if self.transport == 'telnet':
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {'is_alive': True}
            else:
                # SSH
                # Try sending ASCII null byte to maintain the connection alive
                null = chr(0)
                self.device.write_channel(null)
                return {
                    'is_alive': self.device.remote_conn.transport.is_active()
                }
        except (socket.error, EOFError, OSError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {'is_alive': False}

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format
        using the command as the key.
        Example input:
        ['show clock', 'show calendar']
        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}
        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError('Please enter a valid list of commands!')

        for command in commands:
            output = self._send_command(command)
            if 'Invalid input:' in output:
                raise ValueError(
                    'Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def _sanitize_text(self, text, type='underscore'):
        """Remove some weird characters from text."""
        regexp = '[^a-zA-Z0-9]'
        if type == "underscore":
            return re.sub(regexp, '_', text)[0:150]
        elif type == 'erase':
            return re.sub(regexp, '', text)[0:150]

    def _getMIB_value(self, oid):
        """Return a MIB value"""
        command = 'getMIB {}'.format(oid)
        output = self._send_command(command)

        # Check if system supports the command
        if 'No such name.' in output:
            return {}

        return output.split(' = ')[1].strip()

    def _walkMIB_values(self, oid):
        """Return MIB values as a dict"""
        command = 'walkMIB {}'.format(oid)
        output = self._send_command(command)

        # Check if system supports the command
        if 'Cannot translate' in output:
            return {}

        mibs = {}
        for mib in output.splitlines():
            try:
                m = re.search(r"^.*\.(\d+) =(.*)$", mib)
                if m is None:
                    continue
                mibs[m.group(1).strip()] = m.group(2).strip()
            except IndexError:
                continue

        return mibs

    def _get_interface_map(self):
        """Build an interface map that matches interface name to interface index id"""
        if len(self.interface_map) < 1 or "pytest" in sys.modules:
            self.interface_map = {v: k for k,
                                  v in self._walkMIB_values('ifName').items()}
        return self.interface_map

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = u'Hewlett-Packard'
        uptime = -1
        (serial_number, fqdn, os_version, hostname, model,
         interface_list) = (u'Unknown', u'Unknown', u'Unknown', u'Unknown',
                            u'Unknown', [])

        show_system = self._send_command('show system')
        show_uptime = self._send_command('show uptime')
        show_model = self._getMIB_value('sysDescr.0')
        show_int_br = self._send_command('show interfaces brief')

        uptime = dict(zip(("d", "h", "m", "s"), show_uptime.split(':')))
        uptime_seconds = int(float(uptime["s"])) + int(uptime["m"]) * 60 + int(
            uptime["h"]) * 60 * 60 + int(uptime["d"]) * 60 * 60 * 24

        for line in show_system.splitlines():
            if ' System Name ' in line:
                hostname = line.split(' : ')[1].strip()
                if '.' in hostname:
                    fqdn = hostname
                    hostname = hostname.split('.')[0]
            if ' Software revision ' in line:
                os_version = line.split(' : ')[1].split()[0].strip()
            if ' Serial Number ' in line:
                serial_number = line.split(' : ')[2].strip()

        model = show_model.split(', ')[0].strip()

        try:
            split_int_br = re.split(r'-------.*', show_int_br, flags=re.M)[1]

            split_int_br = split_int_br.strip()

            for intf in split_int_br.splitlines():
                try:
                    int_id = intf.split()[0].strip()
                except IndexError:
                    pass
                interface_list.append(int_id)
        except IndexError:
            pass

        return {
            'uptime': uptime_seconds,
            'vendor': vendor,
            'os_version': py23_compat.text_type(os_version),
            'serial_number': py23_compat.text_type(serial_number),
            'model': py23_compat.text_type(model),
            'hostname': py23_compat.text_type(hostname),
            'fqdn': fqdn,
            'interface_list': interface_list
        }

    def get_lldp_neighbors(self):
        """ProCurve implementation of get_lldp_neighbors."""
        lldp = {}
        command = 'show lldp info remote-device'
        output = self._send_command(command)

        # Check if system supports the command
        if 'Invalid input:' in output:
            return {}

        # Process the output to obtain just the LLDP entries
        try:
            split_output = re.split(r'^.*--------.*$', output, flags=re.M)[1]
        except IndexError:
            return {}

        split_output = split_output.strip()

        for lldp_entry in split_output.splitlines():
            # Example, 1         | 00 25 90 3d c3 1f         eth0   eth0      (none).(none)
            local_port = lldp_entry.strip().split(' ', 1)[0].strip()

            if '...' in lldp_entry:
                # ... means something got truncated, we need to look at
                # the details to get the full output
                remote_port, device_id = self._get_lldp_neighbors_detail(
                    local_port)
            else:
                try:
                    (local_port, delim, r_01, r_02, r_03, r_04, r_05, r_06,
                     remote_port, remote_port_desc,
                     device_id) = lldp_entry.split()
                    chassis_id = '{}:{}:{}:{}:{}:{}'.format(
                        r_01, r_02, r_03, r_04, r_05, r_06)
                except ValueError:
                    remote_port, device_id = self._get_lldp_neighbors_detail(
                        local_port)

            entry = {
                'port': py23_compat.text_type(remote_port),
                'hostname': py23_compat.text_type(device_id)
            }
            lldp.setdefault(local_port, [])
            lldp[local_port].append(entry)

        return lldp

    def get_lldp_neighbors_detail(self, interface=''):
        """
        IOS implementation of get_lldp_neighbors_detail.
        Calls get_lldp_neighbors.
        """
        lldp = {}
        lldp_neighbors = self.get_lldp_neighbors()

        interface = py23_compat.text_type(interface)

        # Filter to specific interface
        if interface:
            lldp_data = lldp_neighbors.get(interface)
            if lldp_data:
                lldp_neighbors = {interface: lldp_data}
            else:
                lldp_neighbors = {}

        for interface in lldp_neighbors:
            local_port = interface
            lldp_fields = self._lldp_detail_parser(interface)

            lldp.setdefault(local_port, [])
            lldp[local_port].append({
                'parent_interface':
                u'N/A',
                'remote_port':
                lldp_fields["PortId"],
                'remote_port_description':
                lldp_fields["PortDescr"],
                'remote_chassis_id':
                lldp_fields["ChassisId"],
                'remote_system_name':
                lldp_fields["SysName"],
                'remote_system_description':
                lldp_fields["SystemDescr"],
                'remote_system_capab':
                lldp_fields["SystemCapabilitiesSupported"],
                'remote_system_enable_capab':
                lldp_fields["SystemCapabilitiesEnabled"]
            })

        return lldp

    def _get_lldp_neighbors_detail(self, interface):
        tmp_lldp_details = self._lldp_detail_parser(interface)
        return (tmp_lldp_details['PortId'], tmp_lldp_details['SysName'])

    def _lldp_detail_parser(self, interface):
        """Parse lldp details"""
        lldp = {}
        ifs = self._get_interface_map()

        command = "show lldp info remote-device ethernet {}".format(interface)
        output = self._send_command(command)

        key_mib_table = {'System Descr': 'lldpRemSysDesc',
                         'PortId': 'lldpRemPortId',
                         'PortType': 'lldpRemPortIdSubtype',
                         'PortDescr': 'lldpRemPortDesc',
                         'SysName': 'lldpRemSysName'}

        key_porttype_table = {1: 'interfaceAlias',
                              2: 'portComponent',
                              3: 'macAddress',
                              4: 'networkAddress',
                              5: 'interfaceName',
                              6: 'agentCircuitId',
                              7: 'local'}

        # Check if router supports the command
        if 'Invalid input' in output:
            raise ValueError("Command not supported by network device")

        for lldp_detail in output.splitlines():
            try:
                key, value = map(lambda x: x.strip(), lldp_detail.split(' : '))
            except ValueError:
                continue

            if value.endswith('...'):
                # Procurve OS truncated the entry, thanks. Fetch full value
                # from the MIB
                value = self._getMIB_value(
                    '{}.0.{}.1'.format(key_mib_table[key], ifs[interface]))

            if key == 'PortType' and len(value) == 1:
                value = key_porttype_table[int(value)]
            if key in ('Type', 'Address'):
                key = "AdmMgmt{}".format(key)
            if 'Power' in key or 'Poe' in key:
                key = "Poe{}".format(key)

            if key in ('System Capabilities Supported', 'System Capabilities Enabled'):
                # Parse string values into a list
                value = list(map(lambda x: x.strip(), value.split(',')))

            key = self._sanitize_text(key, 'erase')

            lldp[key] = value

        return lldp

    def get_environment(self):
        """
        Get environment facts.
        cpu is using 1-minute average
        cpu hard-coded to cpu0 (i.e. only a single CPU)
        """
        environment = {}
        show_cpu_1m = self._send_command('show cpu 60')

        sensor_state_table = {
            1: 'unknown',
            2: 'bad',
            3: 'warning',
            4: 'good',
            5: 'notPresent'
        }

        environment.setdefault('cpu', {})
        environment['cpu'][0] = {}
        environment['cpu'][0]['%usage'] = 0.0
        try:
            environment['cpu'][0]['%usage'] = float(
                show_cpu_1m.split('/')[0].strip())
        except KeyError:
            pass

        environment.setdefault('memory', {})
        environment['memory']['used_ram'] = int(
            self._getMIB_value('hpLocalMemAllocBytes.1').replace(',', ''))
        environment['memory']['available_ram'] = int(
            self._getMIB_value('hpLocalMemFreeBytes.1').replace(',', ''))

        # Initialize 'power', 'fan', and 'temperature' to default values
        environment.setdefault('power', {})
        environment.setdefault('fans', {})
        environment.setdefault('temperature', {})

        # Find sensors
        sensortypes = self._walkMIB_values('hpicfSensorObjectId')
        sensorvalues = self._walkMIB_values('hpicfSensorDescr')
        sensorstates = self._walkMIB_values('hpicfSensorStatus')
        for sid in sensortypes.keys():
            stype = sensortypes[sid]
            sname = sensorvalues[sid]
            sreport = sensor_state_table[int(sensorstates[sid])]
            if sreport == 'not present':
                continue

            if stype == 'icfFanSensor':
                env_category = 'fans'
                env_value = {'status': True if sreport == 'good' else False}
            elif stype == 'icfTemperatureSensor':
                env_category = 'temperature'
                env_value = {
                    'temperature': -1.0,
                    'is_alert': True if sreport == 'warning' else False,
                    'is_critical': True if sreport == 'bad' else False
                }
            elif stype == 'icfPowerSupplySensor':
                env_category = 'power'
                env_value = {
                    'capacity': -1.0,
                    'output': -1.0,
                    'status': True if sreport == 'good' else False
                }
            else:
                continue
            environment[env_category][sname] = env_value
        return environment

    def get_config(self, retrieve='all', full=False):

        config = {
            'startup': '',
            'running': '',
            'candidate': ''
        }  # default values

        if retrieve.lower() in ['running', 'all']:
            running_config = self._send_command('show running-config')
            running_config = re.split(
                r'^; .* Configuration Editor;.*$', running_config,
                flags=re.M)[1].strip()
            config['running'] = py23_compat.text_type(running_config)
        if retrieve.lower() in ['startup', 'all']:
            startup_config = self._send_command('show config')
            startup_config = re.split(
                r'^; .* Configuration Editor;.*$', startup_config,
                flags=re.M)[1].strip()
            config['startup'] = py23_compat.text_type(startup_config)
            config['candidate'] = ''
        return config

    def _ping_caps(self):
        """Discover ping capabilities"""
        ping_help = self._send_command('ping help')

        if 'Invalid input' in ping_help:
            raise ValueError("Ping command not supported by network device")

        ping_caps = re.findall(r"^   o \[?([-\w]+)\]? ", ping_help, flags=re.M)
        return ping_caps

    def ping(self,
             destination,
             source=C.PING_SOURCE,
             ttl=C.PING_TTL,
             timeout=C.PING_TIMEOUT,
             size=C.PING_SIZE,
             count=C.PING_COUNT,
             vrf=C.PING_VRF):
        """Execute ping on the device and returns a dictionary with the result."""

        ping_dict = {}
        ping_caps = self._ping_caps()

        command = 'ping {}'.format(destination)
        command += ' repetitions {}'.format(count)
        command += ' timeout {}'.format(timeout)
        if 'data-size' in ping_caps:
            command += ' data-size {}'.format(size)
        if source != '' and 'source' in ping_caps:
            command += ' source {}'.format(source)
        elif source != '':
            return {'error': 'source option not supported by device'}

        output = self._send_command(command).strip()

        # Check if router supports the command
        if 'Invalid input' in output:
            ping_dict['error'] = (output)
        else:
            ping_dict['success'] = {
                'probes_sent': 0,
                'packet_loss': 0,
                'rtt_min': 0.0,
                'rtt_max': 0.0,
                'rtt_avg': 0.0,
                'rtt_stddev': 0.0,
                'results': []
            }

            # Parse ping output
            for line in output.splitlines():
                try:
                    ping_data = re.search(
                        r"^(.*) is alive, iteration (\d+), time = (\d+) ms$",
                        line,
                        flags=re.M)
                    ping_dict['success']['results'].append({
                        'ip_address':
                        py23_compat.text_type(ping_data.group(1)),
                        'rtt':
                        float(ping_data.group(3))
                    })
                    ping_dict['success']['probes_sent'] += 1
                except AttributeError:
                    if line in ('Target did not respond.',
                                'Request timed out.'):
                        ping_dict['success']['probes_sent'] += 1
                        ping_dict['success']['packet_loss'] += 1
                    elif 'packets transmitted,' in line:
                        # The switch displays summary information, use that.
                        ping_data = re.search(
                            r"^(\d+) packets transmitted, (\d+) packets received, (\d+)% packet loss$",
                            line,
                            flags=re.M)
                        ping_dict['success']['probes_sent'] = int(
                            ping_data.group(1))
                        ping_dict['success'][
                            'packet_loss'] = ping_dict['success']['probes_sent'] - int(
                                ping_data.group(2))
                    elif 'round-trip (ms) min/avg/max' in line:
                        ping_data = re.search(
                            r"^round-trip \(ms\) min/avg/max = (\d+)/(\d+)/(\d+)$",
                            line,
                            flags=re.M)
                        ping_dict['success'].update({
                            'rtt_min':
                            float(ping_data.group(1)),
                            'rtt_avg':
                            float(ping_data.group(2)),
                            'rtt_max':
                            float(ping_data.group(3))
                        })
                    else:
                        pass

            rtt_vals = [x['rtt'] for x in ping_dict['success']['results']]
            if ping_dict['success']['rtt_max'] == 0.0:
                # Looks like the device is older and does not provide summary
                # data. Calulate ourselves.
                ping_dict['success'].update({
                    'rtt_min':
                    float(min(rtt_vals)),
                    'rtt_avg':
                    sum(rtt_vals) / float(len(rtt_vals)),
                    'rtt_max':
                    float(max(rtt_vals))
                })

            # Calculate the std deviation
            if len(ping_dict['success']['results']) > 2:
                ss = sum([(x - ping_dict['success']['rtt_avg'])**2
                          for x in rtt_vals])
                pvar = ss / len(ping_dict['success']['results'])
                ping_dict['success']['rtt_stddev'] = float("{:.4f}".format(
                    pvar**0.5))

        return ping_dict

    def get_ntp_servers(self):
        """Returns the NTP servers configuration as dictionary."""

        ntp_servers = {}
        command = 'show sntp'
        output = self._send_command(command)

        if 'Invalid input' in output:
            raise ValueError("Command not supported by network device")

        try:
            split_sntp = re.split(
                r'^  -----.*$', output, flags=re.M)[1].strip()

        except IndexError:
            return {}

        if 'Priority' in output:
            server_idx = 1
        else:
            server_idx = 0

        for line in split_sntp.splitlines():
            split_line = line.split()
            ntp_servers[py23_compat.text_type(split_line[server_idx])] = {}

        return ntp_servers

    def get_arp_table(self, vrf=""):
        """Get arp table information."""
        arp_table = []

        if vrf:
            raise NotImplementedError(
                'No VRF support with this driver/platform.')

        command = 'show arp'
        output = self._send_command(command)

        if 'Invalid input' in output:
            raise ValueError("Command not supported by network device")

        try:
            output = re.split(r'^  -----.*$', output, flags=re.M)[1].strip()
        except IndexError:
            return []

        for line in output.splitlines():
            if len(line.split()) == 4:
                address, mac, eth_type, port = line.split()
            else:
                raise ValueError("Unexpected output from: {}".format(
                    line.split()))

            entry = {
                'interface': py23_compat.text_type(port),
                'mac': napalm.base.helpers.mac(mac),
                'ip': py23_compat.text_type(address),
                'age': 0.0
            }
            arp_table.append(entry)
        return arp_table

    def get_mac_address_table(self):
        """ Get mac table information """

        mac_table = []

        command = 'show vlans'
        output = self._send_command(command)

        if 'Invalid input' in output:
            raise ValueError("Command not supported by network device")

        try:
            output = re.split(r'^  -----.*$', output,
                              flags=re.M)[1].strip()
        except IndexError:
            return []

        for line in output.splitlines():
            # Example:  1              DEFAULT_VLAN Port-based   No    No
            try:
                vlan_id = line.strip().split()[0]
            except IndexError:
                continue

            command = 'show mac-address vlan ' + str(vlan_id)
            output = self._send_command(command)

            if 'Invalid input' in output:
                raise ValueError("Command not supported by network device")

            try:
                output = re.split(r'^  -----.*$', output,
                                  flags=re.M)[1].strip()
            except IndexError:
                continue

            for line in output.splitlines():
                try:
                    mac, port = line.split()
                except IndexError:
                    raise ValueError("Unexpected output from: {}".format(line))

                entry = {
                    'mac': napalm.base.helpers.mac(mac),
                    'interface': port,
                    'vlan': int(vlan_id),
                    'active': True,
                    'static': False,
                    'moves': -1,
                    'last_move': -1.0
                }
                mac_table.append(entry)
        return mac_table

    def get_interfaces(self):
        """Parse brief interface overview"""
        interfaces = {}
        ifs = self._get_interface_map()

        if_types = self._walkMIB_values('ifType')
        if_alias = self._walkMIB_values('ifAlias')
        if_speed = self._walkMIB_values('ifSpeed')
        if_macs = self._walkMIB_values('ifPhysAddress')
        if_mtu = self._walkMIB_values('ifMtu')
        if_adm_state = self._walkMIB_values('ifAdminStatus')
        if_lnk_state = self._walkMIB_values('ifOperStatus')
        if_last_change = self._walkMIB_values('ifLastChange')

        for ifn, idx in ifs.items():
            if if_types[idx] == "6":  # ethernetCsmacd(6)
                interfaces[py23_compat.text_type(ifn)] = {
                    'is_up': True if if_lnk_state[idx] == '1' else False,
                    'is_enabled': True if if_adm_state[idx] == '1' else False,
                    'description': py23_compat.text_type(if_alias[idx]),
                    'last_flapped':
                    -1.0,  # Data makes no sense... unsupported for now.
                    'speed': int(int(if_speed[idx].replace(',', '')) / 1000 / 1000),
                    'mac_address': py23_compat.text_type(if_macs[idx]),
                    'mtu': int(if_mtu[idx]),
                }
        return interfaces

    def get_interfaces_counters(self):
        """Return all interface counters"""
        interface_counters = {}
        ifs = self._get_interface_map()

        if_types = self._walkMIB_values('ifType')
        tx_errors = self._walkMIB_values('ifOutErrors')
        rx_errors = self._walkMIB_values('ifInErrors')
        tx_discards = self._walkMIB_values('ifOutDiscards')
        rx_discards = self._walkMIB_values('ifInDiscards')
        tx_octets = self._walkMIB_values('ifOutOctets')
        rx_octets = self._walkMIB_values('ifInOctets')
        tx_u_pkts = self._walkMIB_values('ifOutUcastPkts')
        rx_u_pkts = self._walkMIB_values('ifInUcastPkts')
        tx_m_pkts = self._walkMIB_values('ifOutMulticastPkts')
        rx_m_pkts = self._walkMIB_values('ifInMulticastPkts')
        tx_b_pkts = self._walkMIB_values('ifOutBroadcastPkts')
        rx_b_pkts = self._walkMIB_values('ifInBroadcastPkts')

        for ifn, idx in ifs.items():
            if if_types[idx] == "6":  # ethernetCsmacd(6)
                interface_counters[py23_compat.text_type(ifn)] = {
                    'tx_errors': int(tx_errors[idx].replace(',', '')),
                    'rx_errors': int(rx_errors[idx].replace(',', '')),
                    'tx_discards': int(tx_discards[idx].replace(',', '')),
                    'rx_discards': int(rx_discards[idx].replace(',', '')),
                    'tx_octets': int(tx_octets[idx].replace(',', '')),
                    'rx_octets': int(rx_octets[idx].replace(',', '')),
                    'tx_unicast_packets': int(tx_u_pkts[idx].replace(',', '')),
                    'rx_unicast_packets': int(rx_u_pkts[idx].replace(',', '')),
                    'tx_multicast_packets': int(tx_m_pkts[idx].replace(
                        ',', '')),
                    'rx_multicast_packets': int(rx_m_pkts[idx].replace(
                        ',', '')),
                    'tx_broadcast_packets': int(tx_b_pkts[idx].replace(
                        ',', '')),
                    'rx_broadcast_packets': int(rx_b_pkts[idx].replace(
                        ',', ''))
                }

        return interface_counters

    def _parse_interface_details(self, interface='all'):
        """Parse detailed interface statistics"""

        interfaces = {}

        command = 'show interfaces ethernet {}'.format(interface)
        output = self._send_command(command)

        for line in output.splitlines():
            line = line.strip()

            if len(line) == 0:
                continue

            if 'Status and Counters' in line:
                entry = {}
                entry['port'] = line.strip().split()[-1]
                cat = ""
                interfaces[entry['port']] = entry
                continue

            if line.endswith(") :"):
                cat = line.split()[0]
                continue

            if line.count(':') == 1:
                key1, value1 = map(lambda x: x.strip(), line.split(':'))
                key1 = self._sanitize_text(key1, 'erase')
                entry["{}{}".format(cat, key1)] = value1
            elif line.count(':') == 2:
                key1, tmp, value2 = map(lambda x: x.strip(), line.split(':'))
                value1, key2 = map(lambda x: x.strip(), tmp.split(' ', 1))
                key1 = self._sanitize_text(key1, 'erase')
                key2 = self._sanitize_text(key1, 'erase')
                entry["{}{}".format(cat, key1)] = value1
                entry["{}{}".format(cat, key2)] = value2
        interfaces[entry['port']] = entry
        return interfaces
