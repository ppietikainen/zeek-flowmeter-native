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

	## Knobs for definitions where extractors differ. All default to F (the plugin's
	## documented behavior); profile "zeek-flowmeter" sets them to what that script does.
	## Gaps from out-of-order input: signed (F) or absolute (T).
	const abs_gap = F &redef;
	## ICMP's 8 header bytes: header (F) or payload (T).
	const icmp_header_as_payload = F &redef;
	## IPv4 echo request/reply only: the 8 bytes count as payload (T), other ICMP stays header.
	const icmp_echo_as_payload = F &redef;
	## Minimum header size: TCP only (F) or over every protocol that has a header (T).
	const min_header_all_protocols = F &redef;
	## IAT, active, idle and bulk times: seconds (F) or microseconds (T). Durations stay seconds.
	const time_microseconds = F &redef;
	## Also write *_bulk_pkts_avg and *_bulk_bytes_avg (per bulk period). The totals and
	## *_bulk_periods are always written; no column changes meaning with a setting.
	const bulk_per_period_avg = F &redef;
	## "default" or "zeek-flowmeter".
	const profile = "default" &redef;

	type Settings: record {
		abs_gap: bool;
		icmp_header_as_payload: bool;
		icmp_echo_as_payload: bool;
		min_header_all_protocols: bool;
		time_microseconds: bool;
		bulk_per_period_avg: bool;
	};

	## The effective knobs (explicit settings or'ed with the profile), read by the plugin.
	global settings: Settings;

	## Semantics. Lengths are IP-layer (the IP total length, so header + payload).
	## *_header is the transport header only, as in CIC (IP header bytes are
	## bytes - payload - header). *_payload is the
	## transport payload from the IP layer, not from sequence numbers. duration is Zeek's own (conn.log's), unset where Zeek writes none;
	## span is first to last packet as seen here (signed with out of order timestamps).
	## Times and
	## IATs are seconds unless time_microseconds; start is the first packet of the connection.
	## Standard deviations are sample (n-1) as in CIC. The last active period is
	## included in active_*. *_skipped counts packets Zeek did not analyze (bad checksum, bad header);
	## they are still included in every other statistic, so conn.log's packet counts equal
	## *_pkts - *_skipped. *_truncated counts packets whose captured length is shorter than the IP length (the
	## capture's snaplen shows here); they count with their IP length. Zeek ignores truncated ICMP, so
	## for ICMP conn.log packets = *_pkts - *_skipped - *_truncated. orig/resp are Zeek's
	## connection roles. Bulk (TCP and UDP only; 0 for ICMP and other protocols): CIC's rule (4+ payload packets within 1 s, uninterrupted
	## by payload from the other side). subflows = 1 + gaps over 1 s.
	## orig/resp follow Zeek's final connection roles (decided at the end, not by arrival).
	type Stats: record {
		start: time &log;
		duration: interval &optional &log;
		span: interval &log;
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
		orig_bulk_periods: count &log;
		orig_bulk_pkts: count &log;
		orig_bulk_bytes: count &log;
		orig_bulk_dur: double &log;
		orig_bulk_pkts_avg: double &optional &log;
		orig_bulk_bytes_avg: double &optional &log;
		orig_skipped: count &log;
		orig_skip_badsum: count &log;
		orig_truncated: count &log;
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
		resp_bulk_periods: count &log;
		resp_bulk_pkts: count &log;
		resp_bulk_bytes: count &log;
		resp_bulk_dur: double &log;
		resp_bulk_pkts_avg: double &optional &log;
		resp_bulk_bytes_avg: double &optional &log;
		resp_skipped: count &log;
		resp_skip_badsum: count &log;
		resp_truncated: count &log;
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

event zeek_init() &priority=10
	{
	if ( profile != "default" && profile != "zeek-flowmeter" )
		Reporter::error(fmt("FlowMeter::profile must be \"default\" or \"zeek-flowmeter\", not \"%s\"", profile));
	local z = profile == "zeek-flowmeter";
	settings = Settings($abs_gap = abs_gap || z,
	                    $icmp_header_as_payload = icmp_header_as_payload,
	                    $icmp_echo_as_payload = icmp_echo_as_payload || z,
	                    $min_header_all_protocols = min_header_all_protocols || z,
	                    $time_microseconds = time_microseconds || z,
	                    $bulk_per_period_avg = bulk_per_period_avg || z);
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
		["profile"] = profile,
		["abs_gap"] = fmt("%s", settings$abs_gap),
		["icmp_header_as_payload"] = fmt("%s", settings$icmp_header_as_payload),
		["icmp_echo_as_payload"] = fmt("%s", settings$icmp_echo_as_payload),
		["min_header_all_protocols"] = fmt("%s", settings$min_header_all_protocols),
		["time_microseconds"] = fmt("%s", settings$time_microseconds),
		["bulk_per_period_avg"] = fmt("%s", settings$bulk_per_period_avg),
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
