#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Checks based on the Phion-MIB for the Barracuda CloudGen Firewall.
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
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.1 --> generalStatusIndex / INTEGER "1,local 2 remote." 
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.2 --> generalStatuslocation / OCTET STRING
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.3 --> ipStatus / OCTET STRING
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.4 --> temperature  "The real temperature value needs to be divided by 10." / TempertureTC
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.5 --> tr1RSSI (mV) / Integer32
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.6 --> tr2RSSI (mV) / Integer32
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.7 --> xpicMode / INTEGER  { disabled ( 0 ) , enabled ( 1 ) } 
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.8 --> siteName / OCTET STRING
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.9 --> systemUptime / OCTET STRING
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.10 --> mcuUptime / OCTET STRING
# .1.3.6.1.4.1.91111.4.80.1.1.1.1.11 --> systemAlarm / INTEGER  { normal ( 0 ) , alarm ( 1 ) } 

from cmk.base.plugins.agent_based.agent_based_api.v1 import (
    register,
    SNMPTree,
    exists,
    Service,
    check_levels,
    startswith,
    Result,
    State,
    render
)


def parse_sysDescr(string_table):
    parsed = {}
    for row in string_table:
        instance_id = row[0]
        parsed[instance_id] = {
            'generalStatusIndex': row[0],
            'generalStatuslocation': row[1],
            'ipStatus': row[2],
            'temperature': row[3],
            'tr1RSSI': row[4],
            'tr2RSSI': row[5],
            'xpicMode': row[6],
            'siteName': row[7],
            'systemUptime': row[8],
            'mcuUptime': row[9],
            'systemAlarm': row[10],
        }
    return parsed

register.snmp_section(
    name='cablefree_diamond_general',
    detect = startswith(".1.3.6.1.2.1.1.1.0", "CableFree GigaBit Ethernet Switch"),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.91111.4.80.1.1.1.1',
        oids=[
            '1',  #generalStatusIndex
            '2',  #generalStatuslocation
            '3',  #ipStatus
            '4',  #temperature
            '5',  #tr1RSSI
            '6',  #tr2RSSI
            '7',  #xpicMode
            '8',  #siteName
            '9',  #systemUptime
            '10', #mcuUptime
            '11', #systemAlarm
        ],
    ),
    parse_function=parse_sysDescr,
)


def discovery_cablefree_diamond_general(section):
    for instance_id in section:
        yield Service(item=instance_id)


def check_cablefree_diamond_general(item, params, section):
    if item not in section:
        return
    
    instance_data = section[item]
    generalStatusIndex = instance_data['generalStatusIndex']
    if generalStatusIndex == '1':
        summary = 'Device is Remote'
    else:
        summary = 'Device is Local'
    
    summary += f", Location is {instance_data['generalStatuslocation']}"
    summary += f", IP is {instance_data['ipStatus']}"
    
    yield from check_levels(
        int(instance_data['temperature']) / 10,
        levels_upper=params.get('temperature', None),
        label='Temperature',
        metric_name=f'cablefree_diamond_general_{item}_temperature',
        render_func=lambda v: f'{v}°C'
    )
    yield from check_levels(
        int(instance_data['tr1RSSI']),
        levels_upper=params.get('tr1RSSI', None),
        label='TR1 RSSI',
        metric_name=f'cablefree_diamond_general_{item}_tr1RSSI',
        render_func=lambda v: f'{v}mV'
    )
    yield from check_levels(
        int(instance_data['tr2RSSI']),
        levels_upper=params.get('tr2RSSI', None),
        label='TR2 RSSI',
        metric_name=f'cablefree_diamond_general_{item}_tr2RSSI',
        render_func=lambda v: f'{v}mV'
    )
    
    if instance_data['xpicMode'] == '1':
        summary += ', XPIC is enabled'
    else:
        summary += ', XPIC is disabled'
    
    summary += f", Site Name is {instance_data['siteName']}"
    summary += f", System Uptime is {instance_data['systemUptime']}"
    summary += f", MCU Uptime is {instance_data['mcuUptime']}"
    
    if instance_data['systemAlarm'] == '1':
        summary += ', System Alarm is active'
    else:
        summary += ', System Alarm is inactive'
    
    yield Result(state=State.OK, summary=summary)


register.check_plugin(
    name='cablefree_diamond_general',
    service_name='Diamond General Status %s',  # %s will be replaced with the instance ID
    discovery_function=discovery_cablefree_diamond_general,
    check_function=check_cablefree_diamond_general,
    check_ruleset_name='cablefree_diamond',
    check_default_parameters={},
)