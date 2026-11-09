# Flow::Meter

Per-connection flow statistics for Zeek, as a native plugin: the feature set of
CICFlowMeter and zeek-flowmeter (packet counts and lengths, inter-arrival
times, TCP flag counts, active and idle periods, bulk transfers, subflows),
computed in C++ over Zeek's own connections.

A tap analyzer sees every packet of every connection, with no per-packet script
events. Each connection gets one row in `flowmeter.log`, keyed by `uid`, so it
joins to `conn.log` and every other Zeek log. Connections, roles, tunnels,
IPv6 and protocols other than TCP and UDP come from Zeek itself.

## Why

CICFlowMeter's feature set is the input of many intrusion detection datasets,
but the CICFlowMeter lines are unmaintained, drop or misread some traffic
(IPv6, ICMP, tunnels, one-packet flows, depending on the version), and keep
every packet of a flow in memory. [zeek-flowmeter](https://github.com/zeek-flowmeter/zeek-flowmeter)
computes the same features in Zeek's script language and keeps Zeek's flows,
but is several times slower than Zeek itself; its authors suggest moving the
computation into a compiled plugin. This is that plugin.

## Build and run

Needs Zeek (developed against 9.0) with its development headers, CMake and a
C++20 compiler.

```
./configure            # finds zeek-config on PATH; see ./configure --help
make
zeek -r trace.pcap Flow::Meter          # with ZEEK_PLUGIN_PATH set, see below
```

To use the plugin from the build directory, put it on Zeek's plugin path.
`ZEEK_PLUGIN_PATH` replaces Zeek's default plugin directory, so keep the
default in the list if you use other plugins:

```
export ZEEK_PLUGIN_PATH=$PWD/build:$(zeek-config --plugin_dir)
```

`cd build && make install` installs it into Zeek's plugin directory instead. `zeek -N
Flow::Meter` shows whether Zeek has loaded it.

## Output

`flowmeter.log`: `ts`, `uid`, and a record `fm` with the statistics (`fm.orig_pkts`,
`fm.iat_mean`, ...). `orig` and `resp` are Zeek's connection roles, decided at
the end of the connection, as in `conn.log`.

`flowmeter_config.log`: one row per setting that shapes the numbers, written
at startup, so every output says how it was made.

## Definitions

Where flow extractors differ, the choice is stated here, and the settings below
change it only where several definitions are defensible.

- **Lengths** are from the IP layer: a packet's length is its IP total length,
  also when the capture kept fewer bytes. `*_header` is the transport header;
  `*_payload` the transport payload from the IP length, not from sequence numbers.
- **Packets Zeek did not analyze** (bad checksum, bad header) are counted in
  `*_skipped` and in every other statistic, so `conn.log`'s packets equal
  `*_pkts - *_skipped`. Packets captured shorter than their IP length are
  counted in `*_truncated`, with their IP length. Zeek ignores truncated ICMP,
  so for ICMP `conn.log`'s packets equal `*_pkts - *_skipped - *_truncated`.
- **Times** are exact integer microseconds from the packet timestamps
  internally, written as seconds (or microseconds, see below). `duration` is
  Zeek's own, unset where `conn.log` has none; `span` is first to last packet as
  seen here, signed when timestamps are out of order.
- **Standard deviations** are sample (n-1). The last active period is included
  in `active_*`. A gap over `activity_timeout` (5 s) ends an active period; a
  gap over `subflow_gap` (1 s) starts a subflow.
- **Bulk transfers** use CICFlowMeter's rule on every protocol: at least
  `bulk_min_packets` payload packets in a row from one side, each less than
  `bulk_gap` (1 s) after the last. `*_bulk_pkts` and `*_bulk_bytes` are totals,
  `*_bulk_periods` the number of periods; no column changes meaning with a setting.
- **ICMP**'s 8-byte header counts as header.

## Settings

All `&redef`, all recorded in `flowmeter_config.log`.

| Setting | Default | Meaning |
|---|---|---|
| `abs_gap` | F | gaps from out-of-order packets: signed (F) or absolute (T) |
| `icmp_header_as_payload` | F | ICMP's 8 bytes: header (F) or payload (T) |
| `icmp_echo_as_payload` | F | IPv4 echo request and reply only: the 8 bytes as payload |
| `min_header_all_protocols` | F | minimum header size over TCP only (F) or every protocol with a header (T) |
| `time_microseconds` | F | IAT, active, idle and bulk times in seconds (F) or microseconds (T) |
| `bulk_per_period_avg` | F | also write `*_bulk_pkts_avg` and `*_bulk_bytes_avg` per bulk period |
| `bulk_min_packets` | 4 | payload packets in a row for a bulk transfer |
| `profile` | "default" | "zeek-flowmeter" sets the above to zeek-flowmeter's definitions |

With `FlowMeter::profile = "zeek-flowmeter"`, the values follow
zeek-flowmeter's definitions, so the two can be compared column by column.

## Compared with zeek-flowmeter

On a 100 MB slice of a public backbone trace (MAWI), with the zeek-flowmeter
profile, against zeek-flowmeter with two fixes (IPv6 extension headers, which it
counts as payload, and its CWR and ECE columns, which it swaps; see
[ppietikainen/zeek-flowmeter](https://github.com/ppietikainen/zeek-flowmeter), branch `fixes`):

- packet, flag and length values equal on all but 3 of 381,644 connections
  without truncated packets or changed roles;
- timing values within 0.25 µs per packet on 99.8% or more, the precision of
  an epoch time held as a double, which zeek-flowmeter uses;
- where they differed beyond that, zeek-flowmeter was wrong.

Run time on the same slice, same machine: Zeek alone 32 s and 3.6 GB, Zeek
with Flow::Meter 52 s and 4.3 GB, Zeek with zeek-flowmeter 208 s and 10.3 GB.

## Tests

`testing/run.py` runs every trace in `testing/traces/` through Zeek with the
plugin and checks each flow against `conn.log` and against known values:
packet and byte counts, start times, payload behind IPv6 extension headers,
role flips, bad checksums, truncated packets, protocols other than TCP and
UDP, the settings, and an ECN handshake. The traces are small synthetic
captures with documentation addresses; the scripts that made them are next
to them.

## Status

Version 0.1.0. Written with an AI coding assistant (Claude, through Claude
Code), against the test traces and the comparison above. It is used as a
reference extractor in work on auditing flow datasets (flowlint, paper in
preparation).
Whether its features serve detection research has not been tested. It is
published for whoever wants to take it further.

## License

BSD 3-Clause, see `COPYING`.
