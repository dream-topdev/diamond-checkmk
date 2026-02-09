#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Checks based on the SNMP-PORTS-MIB for the CableFree Diamond.
#
# Copyright (C) 2021  Marius Rieder <marius.rieder@scs.ch>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Example excerpt from SNMP data:
# .1.3.6.1.4.1.91111.4.80.11.1.2.1.1 --> swPortIndex / Integer32 (1..10)
# .1.3.6.1.4.1.91111.4.80.11.1.2.1.2 --> portLink / INTEGER { linkdown(0), linkup(1) }
# .1.3.6.1.4.1.91111.4.80.11.1.2.1.3 --> portSpeedCurrent / OCTET STRING
# .1.3.6.1.4.1.91111.4.80.11.1.2.1.4 --> portSpeed / INTEGER { speedundefined(0), speed10m(1), speed100m(2), speed1000m(3), speed2500m(4), speed5000m(5), speed10g(6) }
# .1.3.6.1.4.1.91111.4.80.11.1.2.1.5 --> portFlowctrlEnable / INTEGER { disabled(0), enabled(1) }
# .1.3.6.1.4.1.91111.4.80.11.1.2.1.6 --> portFlowctrlRxCur / INTEGER { disabled(0), enabled(1) }
# .1.3.6.1.4.1.91111.4.80.11.1.2.1.7 --> portFlowctrlTxCur / INTEGER { disabled(0), enabled(1) }

from cmk.base.plugins.agent_based.agent_based_api.v1 import (
    register,
    SNMPTree,
    exists,
    Service,
    Result,
    State,
)
from cmk.base.plugins.agent_based.agent_based_api.v1.type_defs import StringTable


# Mapping for port speed values
PORT_SPEED_MAP = {
    '0': 'Undefined',
    '1': '10M',
    '2': '100M',
    '3': '1000M',
    '4': '2500M',
    '5': '5000M',
    '6': '10G',
}

# Mapping for link status
LINK_STATUS_MAP = {
    '0': 'Down',
    '1': 'Up',
}

# Mapping for flow control status
FLOW_CTRL_MAP = {
    '0': 'Disabled',
    '1': 'Enabled',
}


def parse_cablefree_diamond_ports(string_table):
    """Parse port configuration data from SNMP"""
    parsed = {}
    for row in string_table:
        port_index = row[0]
        parsed[port_index] = {
            'swPortIndex': row[0],
            'portLink': row[1],
            'portSpeedCurrent': row[2],
            'portSpeed': row[3],
            'portFlowctrlEnable': row[4],
            'portFlowctrlRxCur': row[5],
            'portFlowctrlTxCur': row[6],
        }
    return parsed


register.snmp_section(
    name='cablefree_diamond_ports',
    detect=exists(".1.3.6.1.4.1.91111.4.80.11.1.2.*"),  # Check if portConfigTable exists
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.91111.4.80.11.1.2.1',
        oids=[
            '1',  # swPortIndex
            '2',  # portLink
            '3',  # portSpeedCurrent
            '4',  # portSpeed
            '5',  # portFlowctrlEnable
            '6',  # portFlowctrlRxCur
            '7',  # portFlowctrlTxCur
        ],
    ),
    parse_function=parse_cablefree_diamond_ports,
)


def discovery_cablefree_diamond_ports(section):
    """Discover all ports"""
    for port_index in section:
        yield Service(item=port_index)


def check_cablefree_diamond_ports(item, section):
    """Check port status and configuration"""
    if item not in section:
        return
    
    port_data = section[item]
    
    # Get port link status
    link_status = LINK_STATUS_MAP.get(port_data['portLink'], 'Unknown')
    port_speed = PORT_SPEED_MAP.get(port_data['portSpeed'], 'Unknown')
    speed_current = port_data['portSpeedCurrent']
    flow_ctrl_enable = FLOW_CTRL_MAP.get(port_data['portFlowctrlEnable'], 'Unknown')
    flow_ctrl_rx = FLOW_CTRL_MAP.get(port_data['portFlowctrlRxCur'], 'Unknown')
    flow_ctrl_tx = FLOW_CTRL_MAP.get(port_data['portFlowctrlTxCur'], 'Unknown')
    
    # Determine state based on link status
    if port_data['portLink'] == '1':
        state = State.OK
        summary = f"Port {item}: Link {link_status}, Speed: {speed_current} ({port_speed})"
    else:
        state = State.WARN
        summary = f"Port {item}: Link {link_status}"
    
    yield Result(state=state, summary=summary)
    
    # Add flow control information
    flow_info = f"Flow Control: Enable={flow_ctrl_enable}, RX={flow_ctrl_rx}, TX={flow_ctrl_tx}"
    yield Result(state=State.OK, notice=flow_info)


register.check_plugin(
    name='cablefree_diamond_ports',
    service_name='Diamond Port %s',  # %s will be replaced with the port index
    discovery_function=discovery_cablefree_diamond_ports,
    check_function=check_cablefree_diamond_ports,
)

