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

import time
from datetime import datetime

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


def parse_uptime_to_minutes(uptime_str):
    """
    Parse uptime string and convert to minutes.
    Expected format: "0d 00:24:25" (days, hours:minutes:seconds)
    """
    try:
        # Remove any extra spaces
        uptime_str = uptime_str.strip()
        
        # Split by space to separate days from time
        parts = uptime_str.split()
        
        total_minutes = 0
        
        if len(parts) >= 2:
            # Parse days (e.g., "0d")
            days_part = parts[0]
            if days_part.endswith('d'):
                days = int(days_part[:-1])  # Remove 'd' and convert to int
                total_minutes += days * 24 * 60
            
            # Parse time part (e.g., "00:24:25")
            time_part = parts[1]
            time_components = time_part.split(':')
            
            if len(time_components) >= 3:
                hours = int(time_components[0])
                minutes = int(time_components[1])
                seconds = int(time_components[2])
                
                total_minutes += hours * 60 + minutes + seconds / 60
            elif len(time_components) == 2:
                # If only hours:minutes format
                hours = int(time_components[0])
                minutes = int(time_components[1])
                total_minutes += hours * 60 + minutes
        else:
            # If no space separator, try to parse as just time
            time_components = uptime_str.split(':')
            if len(time_components) >= 3:
                hours = int(time_components[0])
                minutes = int(time_components[1])
                seconds = int(time_components[2])
                total_minutes += hours * 60 + minutes + seconds / 60
            elif len(time_components) == 2:
                hours = int(time_components[0])
                minutes = int(time_components[1])
                total_minutes += hours * 60 + minutes
        
        return total_minutes
    except (ValueError, AttributeError, IndexError):
        # If parsing fails, return 0 to trigger alarm
        return 0


def detect_restart(current_uptime_minutes, previous_uptime_minutes, current_time):
    """
    Detect if a restart occurred by comparing current and previous uptime values.
    A restart is detected if current uptime is less than previous uptime.
    """
    if previous_uptime_minutes is None:
        return False, None
    
    if current_uptime_minutes < previous_uptime_minutes:
        return True, current_time
    
    return False, None


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
    value_store = get_value_store()
    current_time = time.time()
    
    # Parse uptime values
    system_uptime_str = instance_data['systemUptime']
    mcu_uptime_str = instance_data['mcuUptime']
    
    system_uptime_minutes = parse_uptime_to_minutes(system_uptime_str)
    mcu_uptime_minutes = parse_uptime_to_minutes(mcu_uptime_str)
    
    # Get previous uptime values from value store
    system_uptime_key = f"system_uptime_{item}"
    mcu_uptime_key = f"mcu_uptime_{item}"
    system_restart_history_key = f"system_restart_history_{item}"
    mcu_restart_history_key = f"mcu_restart_history_{item}"
    
    previous_system_uptime = value_store.get(system_uptime_key)
    previous_mcu_uptime = value_store.get(mcu_uptime_key)
    
    # Initialize restart history if not exists
    if system_restart_history_key not in value_store:
        value_store[system_restart_history_key] = []
    if mcu_restart_history_key not in value_store:
        value_store[mcu_restart_history_key] = []
    
    system_restart_history = value_store[system_restart_history_key]
    mcu_restart_history = value_store[mcu_restart_history_key]
    
    # Detect restarts
    system_restart_detected, system_restart_time = detect_restart(
        system_uptime_minutes, previous_system_uptime, current_time
    )
    mcu_restart_detected, mcu_restart_time = detect_restart(
        mcu_uptime_minutes, previous_mcu_uptime, current_time
    )
    
    # Record restarts if detected
    if system_restart_detected and system_restart_time:
        system_restart_history.append({
            'timestamp': system_restart_time,
            'uptime_before': previous_system_uptime,
            'uptime_after': system_uptime_minutes
        })
        # Keep only last 10 restarts to avoid memory issues
        if len(system_restart_history) > 10:
            system_restart_history = system_restart_history[-10:]
        value_store[system_restart_history_key] = system_restart_history
    
    if mcu_restart_detected and mcu_restart_time:
        mcu_restart_history.append({
            'timestamp': mcu_restart_time,
            'uptime_before': previous_mcu_uptime,
            'uptime_after': mcu_uptime_minutes
        })
        # Keep only last 10 restarts to avoid memory issues
        if len(mcu_restart_history) > 10:
            mcu_restart_history = mcu_restart_history[-10:]
        value_store[mcu_restart_history_key] = mcu_restart_history
    
    # Store current uptime values for next check
    value_store[system_uptime_key] = system_uptime_minutes
    value_store[mcu_uptime_key] = mcu_uptime_minutes
    
    # Add uptime metrics for graphing
    yield from check_levels(
        system_uptime_minutes * 60,  # Convert to seconds for better time rendering
        levels_upper=None,  # No thresholds for uptime
        label='System Uptime',
        metric_name=f'cablefree_diamond_general_{item}_system_uptime',
        render_func=render.timespan  # Use CheckMK's built-in time rendering
    )
    
    yield from check_levels(
        mcu_uptime_minutes * 60,  # Convert to seconds for better time rendering
        levels_upper=None,  # No thresholds for uptime
        label='MCU Uptime',
        metric_name=f'cablefree_diamond_general_{item}_mcu_uptime',
        render_func=render.timespan  # Use CheckMK's built-in time rendering
    )
    
    # Build summary
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
    
    if instance_data['systemAlarm'] == '1':
        summary += ', System Alarm is active'
    else:
        summary += ', System Alarm is inactive'
    
    # Check for restarts and set appropriate state
    restart_details = []
    if system_restart_detected:
        restart_details.append("System restart detected")
    if mcu_restart_detected:
        restart_details.append("MCU restart detected")
    
    if restart_details:
        # Add restart details to summary
        summary += f" - {'; '.join(restart_details)}"
        yield Result(state=State.CRIT, summary=summary)
    else:
        yield Result(state=State.OK, summary=summary)


register.check_plugin(
    name='cablefree_diamond_general',
    service_name='Diamond General Status %s',  # %s will be replaced with the instance ID
    discovery_function=discovery_cablefree_diamond_general,
    check_function=check_cablefree_diamond_general,
    check_ruleset_name='cablefree_diamond',
    check_default_parameters={},
)