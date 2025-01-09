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
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.1 --> channelStatusIndex / INTEGER  ( 1 .. 8  ) 
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.2 --> channelStatuslocation / OCTET STRING
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.3 --> txFrequency / INTEGER32 ("kHz")
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.4 --> rxFrequency / INTEGER32 ("kHz")
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.5 --> trSpacing / INTEGER32 ("kHz")
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.6 --> trSide / INTEGER  { low ( 0 ) , high ( 1 ) } 
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.7 --> bandWidth / Integer32 ("kHz")
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.8 --> capacity / Integer32 ("Kbps")
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.9 --> rsl / RslTC (dBm. The real rsl value needs to be divided by 10.)
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.10 --> snr / SnrTc (dB. The real value needs to be divided by 10.)
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.11 --> txPower / Integer32 ("dBm.")
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.12 --> currentTxModulation / ModulationType
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.13 --> currentRxModulation / ModulationType
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.14 --> txMuteStatus / INTEGER  { muteoff ( 0 ) , muteon ( 1 ) } 
# .1.3.6.1.4.1.91111.4.80.1.1.2.1.15 --> modemLockStatus / INTEGER  { unlocked ( 0 ) , locked ( 1 ) } 

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
        'channelStatusIndex': string_table[0][0],
        'channelStatuslocation': string_table[0][1],
        'txFrequency': string_table[0][2],
        'rxFrequency': string_table[0][3],
        'trSpacing': string_table[0][4],
        'trSide': string_table[0][5],
        'bandWidth': string_table[0][6],
        'capacity': string_table[0][7],
        'rsl': string_table[0][8],
        'snr': string_table[0][9],
        'txPower': string_table[0][10],
        'currentTxModulation': string_table[0][11],
        'currentRxModulation': string_table[0][12],
        'txMuteStatus': string_table[0][13],
        'modemLockStatus': string_table[0][14],
    }

register.snmp_section(
    name='cablefree_diamond_channel',
    detect = startswith(".1.3.6.1.4.1.91111.4.80.1.1.1.1.0", "diamond"),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.91111.4.80.1.1.2.1',
        oids=[
            '1',  #channelStatusIndex
            '2',  #channelStatuslocation
            '3',  #txFrequency
            '4',  #rxFrequency
            '5',  #trSpacing
            '6',  #trSide
            '7',  #bandWidth
            '8',  #capacity
            '9',  #rsl
            '10',  #snr
            '11',  #txPower
            '12',  #currentTxModulation
            '13',  #currentRxModulation
            '14',  #txMuteStatus
            '15',  #modemLockStatus
        ],
    ),
    parse_function=parse_sysDescr,
)


def discovery_cablefree_diamond_channel(section):
    if section:
        yield Service()


def check_cablefree_diamond_channel(params, section):    
    summary = f"Channel {section['channelStatusIndex']} is {section['channelStatuslocation']}"
    yield from check_levels(
        int(section['txFrequency']),
        levels_upper=params.get('txFrequency', None),
        label='TX Frequency',
        metric_name='cablefree_diamond_channel_tx_frequency',
        render_func=lambda v: f'{v}kHz'
    )
    yield from check_levels(
        int(section['rxFrequency']),
        levels_upper=params.get('rxFrequency', None),
        label='RX Frequency',
        metric_name='cablefree_diamond_channel_rx_frequency',
        render_func=lambda v: f'{v}kHz'
    )
    yield from check_levels(
        int(section['trSpacing']),
        levels_upper=params.get('trSpacing', None),
        label='TR Spacing',
        metric_name='cablefree_diamond_channel_tr_spacing',
        render_func=lambda v: f'{v}kHz'
    )
    summary += f", TR Side is {section['trSide']}"
    yield from check_levels(
        int(section['bandWidth']),
        levels_upper=params.get('bandWidth', None),
        label='Bandwidth',
        metric_name='cablefree_diamond_channel_band_width',
        render_func=lambda v: f'{v}kHz'
    )
    yield from check_levels(
        int(section['capacity']),
        levels_upper=params.get('capacity', None),
        label='Capacity',
        metric_name='cablefree_diamond_channel_capacity',
        render_func=lambda v: f'{v}Kbps'
    )
    yield from check_levels(
        int(section['rsl']),
        levels_upper=params.get('rsl', None) / 10,
        label='RSL',
        metric_name='cablefree_diamond_channel_rsl',
        render_func=lambda v: f'{v}dBm'
    )
    yield from check_levels(
        int(section['snr']),
        levels_upper=params.get('snr', None) / 10,
        label='SNR',
        metric_name='cablefree_diamond_channel_snr',
        render_func=lambda v: f'{v}dB'
    )
    yield from check_levels(
        int(section['txPower']),
        levels_upper=params.get('txPower', None),
        label='TX Power',
        metric_name='cablefree_diamond_channel_tx_power',
        render_func=lambda v: f'{v}dBm'
    )
    summary += f", Current TX Modulation is {section['currentTxModulation']}"
    summary += f", Current RX Modulation is {section['currentRxModulation']}"
    summary += f", TX Mute Status is {'Muted' if section['txMuteStatus'] == 1 else 'Unmuted'}"
    summary += f", Modem Lock Status is {'Locked' if section['modemLockStatus'] == 1 else 'Unlocked'}"
    yield Result(state=State.OK, summary=summary)


register.check_plugin(
    name='cablefree_diamond_channel',
    service_name='Diamond Channel State',
    discovery_function=discovery_cablefree_diamond_channel,
    check_function=check_cablefree_diamond_channel,
    check_ruleset_name='cablefree_diamond_channel',
    check_default_parameters={},
)