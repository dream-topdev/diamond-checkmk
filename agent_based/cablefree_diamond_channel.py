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
    parsed = {}
    for row in string_table:
        channel_id = row[0]
        parsed[channel_id] = {
            'channelStatusIndex': row[0],
            'channelStatuslocation': row[1],
            'txFrequency': row[2],
            'rxFrequency': row[3],
            'trSpacing': row[4],
            'trSide': row[5],
            'bandWidth': row[6],
            'capacity': row[7],
            'rsl': row[8],
            'snr': row[9],
            'txPower': row[10],
            'currentTxModulation': row[11],
            'currentRxModulation': row[12],
            'txMuteStatus': row[13],
            'modemLockStatus': row[14],
        }
    return parsed

register.snmp_section(
    name='cablefree_diamond_channel',
    detect = startswith(".1.3.6.1.2.1.1.1.0", "CableFree GigaBit Ethernet Switch"),
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
    for channel_id in section:
        yield Service(item=channel_id)


def check_cablefree_diamond_channel(item, params, section):
    if item not in section:
        return
    
    channel_data = section[item]
    summary = f"Channel {channel_data['channelStatusIndex']} is {channel_data['channelStatuslocation']}"
    
    yield from check_levels(
        int(channel_data['txFrequency']),
        levels_upper=params.get('txFrequency', None),
        label='TX Frequency',
        metric_name=f'cablefree_diamond_channel_{item}_tx_frequency',
        render_func=lambda v: f'{v}kHz'
    )
    yield from check_levels(
        int(channel_data['rxFrequency']),
        levels_upper=params.get('rxFrequency', None),
        label='RX Frequency',
        metric_name=f'cablefree_diamond_channel_{item}_rx_frequency',
        render_func=lambda v: f'{v}kHz'
    )
    yield from check_levels(
        int(channel_data['trSpacing']),
        levels_upper=params.get('trSpacing', None),
        label='TR Spacing',
        metric_name=f'cablefree_diamond_channel_{item}_tr_spacing',
        render_func=lambda v: f'{v}kHz'
    )
    summary += f", TR Side is {channel_data['trSide']}"
    yield from check_levels(
        int(channel_data['bandWidth']),
        levels_upper=params.get('bandWidth', None),
        label='Bandwidth',
        metric_name=f'cablefree_diamond_channel_{item}_band_width',
        render_func=lambda v: f'{v}kHz'
    )
    yield from check_levels(
        int(channel_data['capacity']),
        levels_upper=params.get('capacity', None),
        label='Capacity',
        metric_name=f'cablefree_diamond_channel_{item}_capacity',
        render_func=lambda v: f'{v}Kbps'
    )
    yield from check_levels(
        int(channel_data['rsl']) / 10,
        levels_upper=params.get('rsl', None),
        label='RSL',
        metric_name=f'cablefree_diamond_channel_{item}_rsl',
        render_func=lambda v: f'{v}dBm'
    )
    yield from check_levels(
        int(channel_data['snr']) / 10,
        levels_upper=params.get('snr', None),
        label='SNR',
        metric_name=f'cablefree_diamond_channel_{item}_snr',
        render_func=lambda v: f'{v}dB'
    )
    yield from check_levels(
        int(channel_data['txPower']),
        levels_upper=params.get('txPower', None),
        label='TX Power',
        metric_name=f'cablefree_diamond_channel_{item}_tx_power',
        render_func=lambda v: f'{v}dBm'
    )
    summary += f", Current TX Modulation is {channel_data['currentTxModulation']}"
    summary += f", Current RX Modulation is {channel_data['currentRxModulation']}"
    summary += f", TX Mute Status is {'Muted' if channel_data['txMuteStatus'] == '1' else 'Unmuted'}"
    summary += f", Modem Lock Status is {'Locked' if channel_data['modemLockStatus'] == '1' else 'Unlocked'}"
    yield Result(state=State.OK, summary=summary)


register.check_plugin(
    name='cablefree_diamond_channel',
    service_name='Diamond Channel %s',  # %s will be replaced with the channel ID
    discovery_function=discovery_cablefree_diamond_channel,
    check_function=check_cablefree_diamond_channel,
    check_ruleset_name='cablefree_diamond',
    check_default_parameters={},
)