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
from cmk.gui.valuespec import (
    Dictionary,
    Integer,
    Tuple
)

from cmk.gui.plugins.wato import (
    CheckParameterRulespecWithoutItem,
    rulespec_registry,
    RulespecGroupCheckParametersApplications,
)


def _parameter_valuespec_cablefree_diamond():
    return Dictionary(elements=[
        (
            "rsl",
            Tuple(
                title=_("RSL Threshold (dBm)"),
                help=_("Warning and critical thresholds for RSL. Use negative values (e.g., -70 for -70 dBm). Lower values = better signal."),
                elements=[
                    Integer(
                        title=_("Warning at"),
                        default_value=-70,
                        unit=_("dBm"),
                    ),
                    Integer(
                        title=_("Critical at"),
                        default_value=-80,
                        unit=_("dBm"),
                    ),
                ],
            ),
        ),

    ])


rulespec_registry.register(
    CheckParameterRulespecWithoutItem(
        check_group_name='cablefree_diamond',
        group=RulespecGroupCheckParametersApplications,
        parameter_valuespec=_parameter_valuespec_cablefree_diamond,
        title=lambda: _('Cablefree Diamond'),
    )
)
