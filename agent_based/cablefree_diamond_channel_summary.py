"""
Checkmk SNMP check for CableFree Diamond radios – aggregated channel summaries
--------------------------------------------------------------------------

This agent‑based plugin supplements the existing per‑channel check by
producing a handful of services that summarise key metrics across all
radio channels.  Rather than yielding one service per channel, it
creates one service per metric (bandwidth, capacity, RSL, SNR and TX
power) and lists the values for each channel on separate lines.  This
makes it easier to get an overview of the radio’s status when there
are many channels.

The plugin detects CableFree devices by examining the system description
OID (.1.3.6.1.2.1.1.1.0) for the string "CableFree GigaBit Ethernet
Switch".  It then performs a bulk SNMP walk of the channel status table
(.1.3.6.1.4.1.91111.4.80.1.1.2.1) to retrieve the same OIDs used by the
per‑channel check:

    1  channelStatusIndex
    2  channelStatuslocation
    3  txFrequency (kHz)
    4  rxFrequency (kHz)
    5  trSpacing (kHz)
    6  trSide
    7  bandWidth (kHz)
    8  capacity (Kbps)
    9  rsl (dBm × 10)
    10 snr (dB × 10)
    11 txPower (dBm)
    12 currentTxModulation
    13 currentRxModulation
    14 txMuteStatus
    15 modemLockStatus

For each metric listed in the ``SUMMARY_METRICS`` constant below, the
discovery function yields a new service.  The check function then
iterates over every channel in the SNMP section, extracts the relevant
metric and appends it to a list of summary lines.  Numeric values are
converted to appropriate units: bandwidth remains in kHz, capacity in
Kbps, RSL and SNR are divided by 10 to yield dBm/dB, and TX power is
shown in dBm.

If no channels are discovered (e.g. because the device did not respond
or returned no rows), the service reports “no data” instead of an
empty summary.  All summary services are reported with an OK state
because this check does not implement threshold handling; thresholds
should continue to be applied via the per‑channel check.

To enable this plugin, drop it into ``local/lib/check_mk/base/plugins/agent_based/``
on your Checkmk site and run a service discovery.  It can coexist with
the original per‑channel plugin because it registers under a different
SNMP section and check name.
"""

from cmk.base.plugins.agent_based.agent_based_api.v1 import (
    SNMPTree,
    Service,
    Result,
    State,
    register,
    exists,
)

# ---------------------------------------------------------------------------
# SNMP section – fetches the same channel status table as
# cablefree_diamond_channel.  Checkmk caches SNMP responses per host so
# the device is not actually queried twice.
# ---------------------------------------------------------------------------

def _parse_channel_table(string_table):
    parsed = {}
    for row in string_table:
        channel_id = row[0]
        parsed[channel_id] = {
            'channelStatusIndex':    row[0],
            'channelStatuslocation': row[1],
            'txFrequency':           row[2],
            'rxFrequency':           row[3],
            'trSpacing':             row[4],
            'trSide':                row[5],
            'bandWidth':             row[6],
            'capacity':              row[7],
            'rsl':                   row[8],
            'snr':                   row[9],
            'txPower':               row[10],
            'currentTxModulation':   row[11],
            'currentRxModulation':   row[12],
            'txMuteStatus':          row[13],
            'modemLockStatus':       row[14],
        }
    return parsed


register.snmp_section(
    name="cablefree_diamond_channel_summary",
    detect=exists(".1.3.6.1.4.1.91111.4.80.1.1.1.*"),
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.91111.4.80.1.1.2.1",
        oids=["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15"],
    ),
    parse_function=_parse_channel_table,
)


# ---------------------------------------------------------------------------
# Table column definitions
# Each entry is (header_label, extractor_callable).
# The extractor receives a channel_data dict and returns a display string.
# ---------------------------------------------------------------------------

def _rsl(d):
    return f"{int(d['rsl']) / 10.0:.1f} dBm"

def _snr(d):
    return f"{int(d['snr']) / 10.0:.1f} dB"

_COLUMNS = [
    ("Ch",       lambda d: d.get("channelStatusIndex", "?")),
    ("Location", lambda d: d.get("channelStatuslocation", "?")),
    ("Tx Freq",  lambda d: f"{d.get('txFrequency', '?')} kHz"),
    ("Rx Freq",  lambda d: f"{d.get('rxFrequency', '?')} kHz"),
    ("BW",       lambda d: f"{d.get('bandWidth', '?')} kHz"),
    ("Capacity", lambda d: f"{d.get('capacity', '?')} Kbps"),
    ("RSL",      _rsl),
    ("SNR",      _snr),
    ("Tx Pwr",   lambda d: f"{d.get('txPower', '?')} dBm"),
    ("Tx Mod",   lambda d: d.get("currentTxModulation", "?")),
    ("Rx Mod",   lambda d: d.get("currentRxModulation", "?")),
]


def _safe_cell(fn, channel_data):
    """Call an extractor function safely, returning '?' on any error."""
    try:
        return str(fn(channel_data))
    except (ValueError, TypeError, KeyError):
        return "?"


def _build_table(section):
    """Return a plain-text aligned table for all channels in *section*."""
    headers = [hdr for hdr, _ in _COLUMNS]
    extractors = [fn for _, fn in _COLUMNS]

    # Sort channels numerically where possible, else lexicographically.
    def sort_key(k):
        try:
            return (0, int(k))
        except ValueError:
            return (1, k)

    sorted_ids = sorted(section.keys(), key=sort_key)

    # Build all cell strings first so we can compute column widths.
    rows = []
    for channel_id in sorted_ids:
        rows.append([_safe_cell(fn, section[channel_id]) for fn in extractors])

    # Column width = max of header width and widest data cell.
    widths = [
        max(len(headers[i]), max((len(row[i]) for row in rows), default=0))
        for i in range(len(headers))
    ]

    def fmt_row(cells):
        return " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    separator = "-+-".join("-" * w for w in widths)
    lines = [fmt_row(headers), separator] + [fmt_row(row) for row in rows]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Discovery – a single service per device
# ---------------------------------------------------------------------------

def discovery_diamond_channel_summary(section):
    """Yield one summary service when any channel data is present."""
    if section:
        yield Service()


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

def check_diamond_channel_summary(section):
    """Produce an aligned table of all channels and their key metrics."""
    if not section:
        yield Result(state=State.OK, summary="no channel data")
        return

    n = len(section)
    table = _build_table(section)
    yield Result(
        state=State.OK,
        summary=f"{n} channel(s)",
        details=f"{n} channel(s)\n\n{table}",
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

register.check_plugin(
    name="cablefree_diamond_channel_summary",
    # No %s – produces exactly one service named "Diamond Channel Summary".
    service_name="Diamond Channel Summary",
    discovery_function=discovery_diamond_channel_summary,
    check_function=check_diamond_channel_summary,
)