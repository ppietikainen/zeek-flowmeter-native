-- Plugin vs patched CIC on one capture. Usage (in a dir holding the Zeek logs and the CIC CSV):
--   duckdb -c ".read vs-cic.sql"  with CIC=cic.csv.gz, CONN=conn.log.gz, FM=flowmeter.log.gz
-- Rows match on bidirectional 5-tuple + start within 1 ms, one CIC row per Zeek connection
-- (split connections are reported separately). Directions are aligned to Zeek's originator.
create or replace macro canon(x) as lower(trim(x::varchar));
create or replace table conn as
select uid, canon("id.orig_h") oh, "id.orig_p" op, canon("id.resp_h") rh, "id.resp_p" rp, ts from read_json('conn.log.gz', format='newline_delimited');
create or replace table fm as select * from read_json('flowmeter.log.gz', format='newline_delimited');
create or replace table cic as
select canon("Src IP") sip, "Src Port" sport, canon("Dst IP") dip, "Dst Port" dport, Timestamp/1e6 st, * from read_csv('cic.csv.gz');
create or replace table cand as
select c.uid, r.rowid ci, (r.sip = c.oh and r.sport = c.op) same
from conn c join cic r on ((r.sip=c.oh and r.sport=c.op and r.dip=c.rh and r.dport=c.rp) or (r.sip=c.rh and r.sport=c.rp and r.dip=c.oh and r.dport=c.op))
 and abs(r.st - c.ts) < 0.001;
create or replace table pair as
select * from cand where uid in (select uid from cand group by uid having count(*)=1)
  and ci in (select ci from cand group by ci having count(*)=1);
select (select count(*) from conn) conn_rows, (select count(*) from cic) cic_rows, (select count(*) from cand) cand, (select count(*) from pair) paired;

create or replace table cmp as
select p.uid, p.same, f.*, r.* from pair p join fm f using (uid) join (select rowid ci, * from cic) r using (ci);
create or replace macro fw(same, a, b) as case when same then a else b end;
create or replace table concepts as
select * from (
select 'duration_s' c, "Flow Duration"/1e6 cicv, "s.duration" fmv from cmp union all
select 'fwd_pkts', fw(same, "Total Fwd Packet","Total Bwd packets"), "s.orig_pkts" from cmp union all
select 'bwd_pkts', fw(same, "Total Bwd packets","Total Fwd Packet"), "s.resp_pkts" from cmp union all
select 'fwd_bytes', fw(same, "Total Length of Fwd Packet","Total Length of Bwd Packet"), "s.orig_bytes" from cmp union all
select 'bwd_bytes', fw(same, "Total Length of Bwd Packet","Total Length of Fwd Packet"), "s.resp_bytes" from cmp union all
select 'fwd_len_max', fw(same, "Fwd Packet Length Max","Bwd Packet Length Max"), "s.orig_len_max" from cmp union all
select 'fwd_len_min', fw(same, "Fwd Packet Length Min","Bwd Packet Length Min"), "s.orig_len_min" from cmp union all
select 'fwd_len_mean', fw(same, "Fwd Packet Length Mean","Bwd Packet Length Mean"), "s.orig_len_mean" from cmp union all
select 'fwd_len_std', fw(same, "Fwd Packet Length Std","Bwd Packet Length Std"), "s.orig_len_std" from cmp union all
select 'bwd_len_mean', fw(same, "Bwd Packet Length Mean","Fwd Packet Length Mean"), "s.resp_len_mean" from cmp union all
select 'flow_iat_mean_us', "Flow IAT Mean", "s.iat_mean"*1e6 from cmp union all
select 'flow_iat_max_us', "Flow IAT Max", "s.iat_max"*1e6 from cmp union all
select 'flow_iat_min_us', "Flow IAT Min", "s.iat_min"*1e6 from cmp union all
select 'flow_iat_std_us', "Flow IAT Std", "s.iat_std"*1e6 from cmp union all
select 'fwd_iat_total_us', fw(same, "Fwd IAT Total","Bwd IAT Total"), "s.orig_iat_total"*1e6 from cmp union all
select 'fwd_iat_mean_us', fw(same, "Fwd IAT Mean","Bwd IAT Mean"), "s.orig_iat_mean"*1e6 from cmp union all
select 'fwd_iat_max_us', fw(same, "Fwd IAT Max","Bwd IAT Max"), "s.orig_iat_max"*1e6 from cmp union all
select 'fwd_psh', fw(same, "Fwd PSH Flags","Bwd PSH Flags"), "s.orig_psh" from cmp union all
select 'fwd_urg', fw(same, "Fwd URG Flags","Bwd URG Flags"), "s.orig_urg" from cmp union all
select 'fwd_hdr', fw(same, "Fwd Header Length","Bwd Header Length"), "s.orig_header" from cmp union all
select 'bwd_hdr', fw(same, "Bwd Header Length","Fwd Header Length"), "s.resp_header" from cmp union all
select 'len_min', "Packet Length Min", "s.len_min" from cmp union all
select 'len_max', "Packet Length Max", "s.len_max" from cmp union all
select 'len_mean', "Packet Length Mean", "s.len_mean" from cmp union all
select 'len_std', "Packet Length Std", "s.len_std" from cmp union all
select 'fin', "FIN Flag Count", "s.orig_fin"+"s.resp_fin" from cmp union all
select 'syn', "SYN Flag Count", "s.orig_syn"+"s.resp_syn" from cmp union all
select 'rst', "RST Flag Count", "s.orig_rst"+"s.resp_rst" from cmp union all
select 'psh', "PSH Flag Count", "s.orig_psh"+"s.resp_psh" from cmp union all
select 'ack', "ACK Flag Count", "s.orig_ack"+"s.resp_ack" from cmp union all
select 'urg', "URG Flag Count", "s.orig_urg"+"s.resp_urg" from cmp union all
select 'cwr', "CWR Flag Count", "s.orig_cwr"+"s.resp_cwr" from cmp union all
select 'ece', "ECE Flag Count", "s.orig_ece"+"s.resp_ece" from cmp union all
select 'fwd_seg_avg', fw(same, "Fwd Segment Size Avg","Bwd Segment Size Avg"), "s.orig_len_mean" from cmp union all
select 'subflow_fwd_pkts', fw(same, "Subflow Fwd Packets","Subflow Bwd Packets"), "s.orig_pkts"/"s.subflows"::double from cmp union all
select 'subflow_fwd_bytes', fw(same, "Subflow Fwd Bytes","Subflow Bwd Bytes"), "s.orig_bytes"/"s.subflows"::double from cmp union all
select 'fwd_init_win', fw(same, "FWD Init Win Bytes","Bwd Init Win Bytes"), "s.orig_init_win" from cmp union all
select 'bwd_init_win', fw(same, "Bwd Init Win Bytes","FWD Init Win Bytes"), "s.resp_init_win" from cmp union all
select 'fwd_act_data', fw(same, "Fwd Act Data Pkts","Bwd Act Data Pkts"), "s.orig_data_pkts" from cmp union all
select 'fwd_seg_min', fw(same, "Fwd Seg Size Min","Bwd Seg Size Min"), "s.orig_min_seg" from cmp union all
select 'active_mean_us', "Active Mean", "s.active_mean"*1e6 from cmp union all
select 'active_max_us', "Active Max", "s.active_max"*1e6 from cmp union all
select 'idle_mean_us', "Idle Mean", "s.idle_mean"*1e6 from cmp union all
select 'idle_max_us', "Idle Max", "s.idle_max"*1e6 from cmp union all
select 'fwd_bulk_pkts_avg', fw(same, "Fwd Packet/Bulk Avg","Bwd Packet/Bulk Avg"), case when "s.orig_bulk_states">0 then "s.orig_bulk_pkts"/"s.orig_bulk_states"::double else 0 end from cmp union all
select 'fwd_bulk_bytes_avg', fw(same, "Fwd Bytes/Bulk Avg","Bwd Bytes/Bulk Avg"), case when "s.orig_bulk_states">0 then "s.orig_bulk_bytes"/"s.orig_bulk_states"::double else 0 end from cmp union all
select 'fwd_payload_total', fw(same, "Fwd Segment Payload Length Total","Bwd Segment Payload Length Total"), "s.orig_payload" from cmp union all
select 'fwd_payload_max', fw(same, "Fwd Segment Payload Length Max","Bwd Segment Payload Length Max"), "s.orig_pay_max" from cmp union all
select 'fwd_payload_min', fw(same, "Fwd Segment Payload Length Min","Bwd Segment Payload Length Min"), "s.orig_pay_min" from cmp union all
select 'fwd_payload_mean', fw(same, "Fwd Segment Payload Length Mean","Bwd Segment Payload Length Mean"), "s.orig_pay_mean" from cmp union all
select 'fwd_payload_std', fw(same, "Fwd Segment Payload Length Std","Bwd Segment Payload Length Std"), "s.orig_pay_std" from cmp
);
-- equal = relative difference under 1e-6 or both ~0; close = within 1%
select c concept, count(*) n,
  round(avg((abs(cicv-fmv) <= 1e-6*greatest(abs(cicv),abs(fmv),1))::int),4) equal,
  round(avg((abs(cicv-fmv) <= 0.01*greatest(abs(cicv),abs(fmv),1))::int),4) within1pct,
  round(corr(cicv,fmv),4) pearson
from concepts group by c order by equal;
