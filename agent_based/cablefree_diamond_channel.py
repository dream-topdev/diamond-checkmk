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
    render,
    get_value_store,
)
from cmk.base.plugins.agent_based.agent_based_api.v1.type_defs import StringTable


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
    value_store = get_value_store()
    
    # State management keys
    bandwidth_key = f"cablefree_diamond_channel_{item}_bandwidth"
    tx_modulation_key = f"cablefree_diamond_channel_{item}_tx_modulation"
    rx_modulation_key = f"cablefree_diamond_channel_{item}_rx_modulation"
    
    summary = f"Channel {channel_data['channelStatusIndex']} is {channel_data['channelStatuslocation']}"
    
    yield from check_levels(
        int(channel_data['txFrequency']),
        levels_upper=params.get('txFrequency', None),
        label='TX Frequency',
        metric_name=f'cablefree_diamond_channel_{item}_tx_frequency',
        render_func=lambda v: normalize_value(v, 1000, ['kHz', 'MHz', 'GHz'])
    )
    yield from check_levels(
        int(channel_data['rxFrequency']),
        levels_upper=params.get('rxFrequency', None),
        label='RX Frequency',
        metric_name=f'cablefree_diamond_channel_{item}_rx_frequency',
        render_func=lambda v: normalize_value(v, 1000, ['kHz', 'MHz', 'GHz'])
    )
    yield from check_levels(
        int(channel_data['trSpacing']),
        levels_upper=params.get('trSpacing', None),
        label='TR Spacing',
        metric_name=f'cablefree_diamond_channel_{item}_tr_spacing',
        render_func=lambda v: normalize_value(v, 1000, ['kHz', 'MHz', 'GHz'])
    )
    summary += f", TR Side is {channel_data['trSide']}"
    
    # Bandwidth change monitoring
    current_bandwidth = int(channel_data['bandWidth'])
    previous_bandwidth = value_store.get(bandwidth_key, current_bandwidth)
    
    if previous_bandwidth != current_bandwidth:
        bandwidth_change = current_bandwidth - previous_bandwidth
        if bandwidth_change < 0:
            summary += f", Bandwidth decreased by {abs(bandwidth_change)}kHz"
            yield Result(state=State.WARN, summary=summary)
        else:
            summary += f", Bandwidth increased by {bandwidth_change}kHz"
    
    value_store[bandwidth_key] = current_bandwidth
    
    yield from check_levels(
        current_bandwidth,
        levels_upper=params.get('bandWidth', None),
        label='Bandwidth',
        metric_name=f'cablefree_diamond_channel_{item}_band_width',
        render_func=lambda v: normalize_value(v, 1000, ['kHz', 'MHz', 'GHz'])
    )
    
    # Get bandwidth values
    current_capacity = int(channel_data['capacity'])
    
    
    yield from check_levels(
        int(channel_data['capacity']),
        levels_upper=params.get('capacity', None),
        label='Capacity',
        metric_name=f'cablefree_diamond_channel_{item}_capacity',
        render_func=lambda v: normalize_value(v, 1000, ['Kbps', 'Mbps', 'Gbps'])
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
    
    # Modulation change monitoring
    current_tx_modulation = channel_data['currentTxModulation']
    current_rx_modulation = channel_data['currentRxModulation']
    
    previous_tx_modulation = value_store.get(tx_modulation_key, current_tx_modulation)
    previous_rx_modulation = value_store.get(rx_modulation_key, current_rx_modulation)
    
    # Check for modulation changes from higher to lower
    # Assuming modulation values are numeric where higher numbers = higher modulation
    try:
        tx_modulation_change = int(current_tx_modulation) - int(previous_tx_modulation)
        rx_modulation_change = int(current_rx_modulation) - int(previous_rx_modulation)
        
        if tx_modulation_change < 0:
            summary += f", TX Modulation decreased from {previous_tx_modulation} to {current_tx_modulation}"
            yield Result(state=State.WARN, summary=summary)
        elif tx_modulation_change > 0:
            summary += f", TX Modulation increased from {previous_tx_modulation} to {current_tx_modulation}"
        
        if rx_modulation_change < 0:
            summary += f", RX Modulation decreased from {previous_rx_modulation} to {current_rx_modulation}"
            yield Result(state=State.WARN, summary=summary)
        elif rx_modulation_change > 0:
            summary += f", RX Modulation increased from {previous_rx_modulation} to {current_rx_modulation}"
            
    except ValueError:
        # If modulation values are not numeric, just display current values
        pass
    
    value_store[tx_modulation_key] = current_tx_modulation
    value_store[rx_modulation_key] = current_rx_modulation
    
    summary += f", Current TX Modulation is {current_tx_modulation}"
    summary += f", Current RX Modulation is {current_rx_modulation}"
    summary += f", TX Mute Status is {'Muted' if channel_data['txMuteStatus'] == '1' else 'Unmuted'}"
    
    # Check modem lock status - CRITICAL if unlocked (link down)
    modem_lock_status = channel_data['modemLockStatus']
    if modem_lock_status == '0':  # Unlocked
        summary += f", Modem Lock Status is Unlocked (LINK DOWN)"
        yield Result(state=State.CRIT, summary=summary)
        return  # Return early with CRITICAL state
    else:
        summary += f", Modem Lock Status is Locked"
    
    yield Result(state=State.OK, summary=summary)


register.check_plugin(
    name='cablefree_diamond_channel',
    service_name='Diamond Channel %s',  # %s will be replaced with the channel ID
    discovery_function=discovery_cablefree_diamond_channel,
    check_function=check_cablefree_diamond_channel,
    check_ruleset_name='cablefree_diamond',
    check_default_parameters={},
)


def normalize_value(value, base=1000, units=None):
    """
    Normalize a value to K, M, G units.
    base: 1000 for kHz/MHz/GHz or Kbps/Mbps/Gbps
    units: list of units, e.g. ['kHz', 'MHz', 'GHz']
    """
    if units is None:
        units = ['K', 'M', 'G']
    value = float(value)
    for unit in units:
        if value < base:
            return f"{value:.2f}{unit}"
        value /= base
    return f"{value * base:.2f}{units[-1]}"  # fallback to largest unit