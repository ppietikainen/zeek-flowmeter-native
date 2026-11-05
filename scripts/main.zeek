##! Per-connection flow statistics from the Flow::Meter native plugin.
##! One row per connection in flowmeter.log, keyed by uid.

module FlowMeter;

export {
	redef enum Log::ID += { LOG };

	## A gap between packets above this ends an active period (CIC: 5 s).
	const activity_timeout = 5sec &redef;

	## Lengths are IP-layer (total length field). Times in seconds.
	## orig/resp follow Zeek's connection roles, not the first packet seen.
	type Stats: record {
		duration: interval &log;
		orig_pkts: count &log;
		orig_bytes: count &log;
		orig_payload: count &log;
		orig_header: count &log;
		orig_len_min: double &log;
		orig_len_max: double &log;
		orig_len_mean: double &log;
		orig_len_std: double &log;
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
		resp_pkts: count &log;
		resp_bytes: count &log;
		resp_payload: count &log;
		resp_header: count &log;
		resp_len_min: double &log;
		resp_len_max: double &log;
		resp_len_mean: double &log;
		resp_len_std: double &log;
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
		s: Stats &log;
	};

	global flow_done: event(uid: string, s: Stats);
	global log_flowmeter: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_flowmeter, $path="flowmeter"]);
	}

event FlowMeter::flow_done(uid: string, s: Stats)
	{
	Log::write(LOG, [$ts=network_time(), $uid=uid, $s=s]);
	}
