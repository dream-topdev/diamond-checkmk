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
    return {
        'generalStatusIndex': string_table[0][0],
        'generalStatuslocation': string_table[0][1],
        'ipStatus': string_table[0][2],
        'temperature': string_table[0][3],
        'tr1RSSI': string_table[0][4],
        'tr2RSSI': string_table[0][5],
        'xpicMode': string_table[0][6],
        'siteName': string_table[0][7],
        'systemUptime': string_table[0][8],
        'mcuUptime': string_table[0][9],
        'systemAlarm': string_table[0][10],
    }

register.snmp_section(
    name='cablefree_diamond_general',
    detect = startswith(".1.3.6.1.4.1.91111.4.80.1.1.1.1.0", "diamond"),
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
    if section:
        yield Service()


def check_cablefree_diamond_general(params, section):
    generalStatusIndex = section['generalStatusIndex']
    if generalStatusIndex == '1':
        summary  = 'Device is Remote'
    else:
        summary  = 'Device is Local'
    
    summary += ', Location is %s' % section['generalStatuslocation']
    summary += ', IP is %s' % section['ipStatus']    
    yield from check_levels(
        int(section['temperature']) / 10,
        levels_upper=params.get('temperature', None),
        label='Temperature',
        metric_name='cablefree_diamond_general_temperature',
        render_func=lambda v: f'{v}°C'
    )
    yield from check_levels(
        int(section['tr1RSSI']),
        levels_upper=params.get('tr1RSSI', None),
        label='TR1 RSSI',
        metric_name='cablefree_diamond_general_tr1RSSI',
        render_func=lambda v: f'{v}mV'
    )
    yield from check_levels(
        int(section['tr2RSSI']),
        levels_upper=params.get('tr2RSSI', None),
        label='TR2 RSSI',
        metric_name='cablefree_diamond_general_tr2RSSI',
        render_func=lambda v: f'{v}mV'
    )
    if section['xpicMode'] == '1':
        summary += ', XPIC is enabled'
    else:
        summary += ', XPIC is disabled'
    summary += ', Site Name is %s' % section['siteName']
    summary += ', System Uptime is %s' % section['systemUptime']
    summary += ', MCU Uptime is %s' % section['mcuUptime']
    if section['systemAlarm'] == '1':
        summary += ', System Alarm is active'
    else:
        summary += ', System Alarm is inactive'
    
    yield Result(state=State.OK, summary=summary)


register.check_plugin(
    name='cablefree_diamond_general',
    service_name='Diamond General Status',
    discovery_function=discovery_cablefree_diamond_general,
    check_function=check_cablefree_diamond_general,
    check_ruleset_name='cablefree_diamond',
    check_default_parameters={},
)