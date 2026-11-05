##! Per-connection flow statistics from the Flow::Meter native plugin.
##! One row per connection in flowmeter.log, keyed by uid.

@load ./version

module FlowMeter;

export {
	redef enum Log::ID += { LOG, CONFIG_LOG };

	## A gap between packets above this ends an active period (CIC: 5 s).
	const activity_timeout = 5sec &redef;
	## A gap above this starts a new subflow.
	const subflow_gap = 1sec &redef;
	## Payload packets closer together than this can form a bulk transfer.
	const bulk_gap = 1sec &redef;
	## Payload packets in a row needed to count as a bulk transfer.
	const bulk_min_packets = 4 &redef;

	## Semantics. Lengths are IP-layer (the IP total length, so header + payload).
	## *_header is the transport header only, as in CIC (IP header bytes are
	## bytes - payload - header). *_payload is the
	## transport payload from the IP layer, not from sequence numbers. Times and
	## IATs are seconds; start is the first packet of the connection.
	## Standard deviations are sample (n-1) as in CIC. The last active period is
	## included in active_*. *_skipped counts packets Zeek did not analyze (bad checksum, bad header);
	## they are still included in every other statistic, so conn.log's packet counts equal
	## *_pkts - *_skipped. Truncated packets count with their on-wire length. orig/resp are Zeek's
	## connection roles. Bulk: CIC's rule (4+ payload packets within 1 s, uninterrupted
	## by payload from the other side). subflows = 1 + gaps over 1 s.
	## orig/resp follow Zeek's connection roles, not the first packet seen.
	type Stats: record {
		start: time &log;
		duration: interval &log;
		orig_pkts: count &log;
		orig_bytes: count &log;
		orig_payload: count &log;
		orig_header: count &log;
		orig_len_min: double &log;
		orig_len_max: double &log;
		orig_len_mean: double &log;
		orig_len_std: double &log;
		orig_pay_min: double &log;
		orig_pay_max: double &log;
		orig_pay_mean: double &log;
		orig_pay_std: double &log;
		orig_iat_total: double &log;
		orig_iat_min: double &log;
		orig_iat_max: double &log;
		orig_iat_mean: double &log;
		orig_iat_std: double &log;
		orig_psh: count &log;
		orig_urg: count &log;
		orig_fin: count &log;
		orig_syn: count &log;
		orig_rst: count &log;
		orig_ack: count &log;
		orig_cwr: count &log;
		orig_ece: count &log;
		orig_data_pkts: count &log;
		orig_min_seg: count &log;
		orig_init_win: count &log;
		orig_bulk_states: count &log;
		orig_bulk_pkts: count &log;
		orig_bulk_bytes: count &log;
		orig_bulk_dur: double &log;
		orig_skipped: count &log;
		orig_skip_badsum: count &log;
		resp_pkts: count &log;
		resp_bytes: count &log;
		resp_payload: count &log;
		resp_header: count &log;
		resp_len_min: double &log;
		resp_len_max: double &log;
		resp_len_mean: double &log;
		resp_len_std: double &log;
		resp_pay_min: double &log;
		resp_pay_max: double &log;
		resp_pay_mean: double &log;
		resp_pay_std: double &log;
		resp_iat_total: double &log;
		resp_iat_min: double &log;
		resp_iat_max: double &log;
		resp_iat_mean: double &log;
		resp_iat_std: double &log;
		resp_psh: count &log;
		resp_urg: count &log;
		resp_fin: count &log;
		resp_syn: count &log;
		resp_rst: count &log;
		resp_ack: count &log;
		resp_cwr: count &log;
		resp_ece: count &log;
		resp_data_pkts: count &log;
		resp_min_seg: count &log;
		resp_init_win: count &log;
		resp_bulk_states: count &log;
		resp_bulk_pkts: count &log;
		resp_bulk_bytes: count &log;
		resp_bulk_dur: double &log;
		resp_skipped: count &log;
		resp_skip_badsum: count &log;
		len_min: double &log;
		len_max: double &log;
		len_mean: double &log;
		len_std: double &log;
		len_var: double &log;
		subflows: count &log;
		iat_total: double &log;
		iat_min: double &log;
		iat_max: double &log;
		iat_mean: double &log;
		iat_std: double &log;
		active_n: count &log;
		active_min: double &log;
		active_max: double &log;
		active_mean: double &log;
		active_std: double &log;
		idle_n: count &log;
		idle_min: double &log;
		idle_max: double &log;
		idle_mean: double &log;
		idle_std: double &log;
	};

	type Info: record {
		ts: time &log;
		uid: string &log;
		fm: Stats &log;
	};

	## One row per setting that shapes the numbers in flowmeter.log, written at
	## startup to flowmeter_config.log (a separate table, read whole; there is no join key).
	type Config: record {
		key: string &log;
		value: string &log;
	};

	global flow_done: event(uid: string, s: Stats);
	global log_flowmeter: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_flowmeter, $path="flowmeter"]);
	Log::create_stream(CONFIG_LOG, [$columns=Config, $path="flowmeter_config"]);
	}

event zeek_init() &priority=-5
	{
	local c: table[string] of string = {
		["plugin_version"] = version,
		["zeek_version"] = zeek_version(),
		["activity_timeout_s"] = fmt("%f", interval_to_double(activity_timeout)),
		["subflow_gap_s"] = fmt("%f", interval_to_double(subflow_gap)),
		["bulk_gap_s"] = fmt("%f", interval_to_double(bulk_gap)),
		["bulk_min_packets"] = fmt("%d", bulk_min_packets),
		["tcp_inactivity_timeout_s"] = fmt("%f", interval_to_double(tcp_inactivity_timeout)),
		["udp_inactivity_timeout_s"] = fmt("%f", interval_to_double(udp_inactivity_timeout)),
		["icmp_inactivity_timeout_s"] = fmt("%f", interval_to_double(icmp_inactivity_timeout)),
		["tcp_attempt_delay_s"] = fmt("%f", interval_to_double(tcp_attempt_delay)),
		["tcp_close_delay_s"] = fmt("%f", interval_to_double(tcp_close_delay)),
		["tcp_reset_delay_s"] = fmt("%f", interval_to_double(tcp_reset_delay)),
		["tcp_partial_close_delay_s"] = fmt("%f", interval_to_double(tcp_partial_close_delay)),
		["ignore_checksums"] = fmt("%s", ignore_checksums)
	};
	for ( k, v in c )
		Log::write(CONFIG_LOG, [$key=k, $value=v]);
	}

event FlowMeter::flow_done(uid: string, s: Stats)
	{
	Log::write(LOG, [$ts=s$start, $uid=uid, $fm=s]);
	}
