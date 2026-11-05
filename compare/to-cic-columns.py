#!/usr/bin/env python3
"""Plugin output as a CICFlowMeter-shaped parquet, so flowlint's CSV checks apply.

    to-cic-columns.py CONN_LOG FLOWMETER_LOG OUT.parquet

Column names follow the Java CICFlowMeter header; times are microseconds as there.
orig/resp become Src/Dst. Features the plugin does not produce are left out, not zeroed. fwd_pkts_tot and
flow_iat.avg repeat two columns under zeek-flowmeter's names: flowlint gates its
CICFlowMeter checks on that naming, and this is a CICFlowMeter-feature extractor in Zeek.
"""
import sys
import duckdb

conn, fm, out = sys.argv[1:4]
con = duckdb.connect()
rd = lambda p: f"read_json_auto('{p}', format='newline_delimited', sample_size=-1)"
con.execute(f"""copy (
select c."id.orig_h" "Src IP", c."id.orig_p" "Src Port", c."id.resp_h" "Dst IP", c."id.resp_p" "Dst Port",
  case c.proto when 'tcp' then 6 when 'udp' then 17 when 'icmp' then 1 when 'icmp6' then 58 end "Protocol",
  m.ts "Timestamp", m."s.duration"*1e6 "Flow Duration",
  m."s.orig_pkts" "Total Fwd Packet", m."s.orig_pkts" "fwd_pkts_tot", m."s.iat_mean"*1e6 "flow_iat.avg", m."s.resp_pkts" "Total Bwd packets",
  m."s.orig_bytes" "Total Length of Fwd Packet", m."s.resp_bytes" "Total Length of Bwd Packet",
  m."s.len_max" "Packet Length Max", m."s.len_min" "Packet Length Min",
  m."s.orig_syn"+m."s.resp_syn" "SYN Flag Count", m."s.orig_fin"+m."s.resp_fin" "FIN Flag Count",
  m."s.orig_rst"+m."s.resp_rst" "RST Flag Count",
  m."s.orig_init_win" "FWD Init Win Bytes", m."s.resp_init_win" "Bwd Init Win Bytes",
  m."s.orig_header" "Fwd Header Length",
  m."s.iat_mean"*1e6 "Flow IAT Mean", m."s.iat_max"*1e6 "Flow IAT Max", m."s.iat_min"*1e6 "Flow IAT Min",
  m."s.idle_min"*1e6 "Idle Min", m."s.active_max"*1e6 "Active Max",
  case when m."s.duration">0 then (m."s.orig_bytes"+m."s.resp_bytes")/m."s.duration" end "Flow Bytes/s",
  case when m."s.duration">0 then (m."s.orig_pkts"+m."s.resp_pkts")/m."s.duration" end "Flow Packets/s"
from {rd(conn)} c join {rd(fm)} m using (uid)) to '{out}' (format parquet)""")
print(con.execute(f"select count(*) from read_parquet('{out}')").fetchone()[0], "rows", file=sys.stderr)
