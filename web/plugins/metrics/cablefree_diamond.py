#!/usr/bin/env python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Copyright (C) 2021  Marius Rieder <marius.rieder@durchmesser.ch>
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

from cmk.gui.i18n import _

from cmk.gui.plugins.metrics import metric_info, check_metrics, perfometer_info, MB


# metrics for general
metric_info["cablefree_diamond_general_temperature"] = {
    "title": _("Temperature"),
    "unit": "°C",
    "color": "#00e060",
}
metric_info["cablefree_diamond_general_tr1RSSI"] = {
    "title": _("TR1 RSSI"),
    "unit": "mV",
    "color": "#00e060",
}
metric_info["cablefree_diamond_general_tr2RSSI"] = {
    "title": _("TR2 RSSI"),
    "unit": "mV",
    "color": "#00e060",
}
check_metrics["check_mk-cablefree_diamond_general"] = {
    "temperature": {
        "name": "cablefree_diamond_general_temperature",
    },
    "tr1RSSI": {
        "name": "cablefree_diamond_general_tr1RSSI",
    },
    "tr2RSSI": {
        "name": "cablefree_diamond_general_tr2RSSI",
    },
}

# metrics for channel
metric_info["cablefree_diamond_channel_tx_frequency"] = {
    "title": _("TX Frequency"),
    "unit": "kHz",
    "color": "#00e060",
}
metric_info["cablefree_diamond_channel_rx_frequency"] = {
    "title": _("RX Frequency"),
    "unit": "kHz",
    "color": "#00e060",
}
metric_info["cablefree_diamond_channel_band_width"] = {
    "title": _("Bandwidth"),
    "unit": "kHz",
    "color": "#00e060",
}
metric_info["cablefree_diamond_channel_capacity"] = {
    "title": _("Capacity"),
    "unit": "Kbps",
    "color": "#00e060",
}
metric_info["cablefree_diamond_channel_rsl"] = {
    "title": _("RSL"),
    "unit": "dBm",
    "color": "#00e060",
}
metric_info["cablefree_diamond_channel_snr"] = {
    "title": _("SNR"),
    "unit": "dB",
    "color": "#00e060",
}
check_metrics["check_mk-cablefree_diamond_channel"] = {
    "txFrequency": {
        "name": "cablefree_diamond_channel_tx_frequency",
    },
    "rxFrequency": {
        "name": "cablefree_diamond_channel_rx_frequency",
    },
    "bandWidth": {
        "name": "cablefree_diamond_channel_band_width",
    },
    "capacity": {
        "name": "cablefree_diamond_channel_capacity",
    },
    "rsl": {
        "name": "cablefree_diamond_channel_rsl",
    },
    "snr": {
        "name": "cablefree_diamond_channel_snr",
    },
    "txPower": {
        "name": "cablefree_diamond_channel_tx_power",
    },
}
