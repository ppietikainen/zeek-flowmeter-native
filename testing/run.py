#!/usr/bin/env python3
"""Plugin tests. Usage: run.py [ZEEK_IMAGE]  (needs podman; plugin built in ./build).

Every trace is run through Zeek with the plugin; for each flow:
  - packets, IP bytes equal conn.log's, start equals conn.log's ts
  - payload bytes equal the known value (exthdr: 100/200; others: conn.log - headers is
    not exact, so only checked for exthdr)
"""
import json, os, subprocess, sys, tempfile

img = sys.argv[1] if len(sys.argv) > 1 else "localhost/zeek-kit:9.0.0-ja4cpp"
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = 0

def run(trace, extra=(), ignore_checksums=True):
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o777)
        subprocess.run(["podman", "run", "--rm", "-v", f"{root}:/src:ro,z", "-v", f"{d}:/o:z", "-w", "/o",
                        "-e", "ZEEK_PLUGIN_PATH=/src/build", "--entrypoint", "zeek", img, *(["-C"] if ignore_checksums else []), "-r",
                        f"/src/testing/traces/{trace}", "Flow::Meter", "LogAscii::use_json=T", *extra],
                       check=True, capture_output=True)
        rd = lambda n: [json.loads(l) for l in open(f"{d}/{n}.log")]
        return rd("conn"), rd("flowmeter")

def check(ok, msg):
    global fails
    if not ok:
        fails += 1
        print("FAIL", msg)

for trace in ("flowdef.pcap", "flowdef-b.pcap", "exthdr.pcap", "other.pcap", "flip.pcap", "flip2.pcap", "trunc.pcap", "knobs.pcap"):
    conn, fm = run(trace)
    c = {r["uid"]: r for r in conn}
    check(len(fm) == len(conn), f"{trace}: {len(fm)} flowmeter rows vs {len(conn)} conn rows")
    for r in fm:
        k = c[r["uid"]]
        # Identity: packets - skipped (- truncated, ICMP only: Zeek ignores truncated ICMP) = conn.log
        icmp = k["proto"] == "icmp"
        for side in ("orig", "resp"):
            sub = r[f"fm.{side}_skipped"] + (r[f"fm.{side}_truncated"] if icmp else 0)
            check(r[f"fm.{side}_pkts"] - sub == k[f"{side}_pkts"],
                  f"{trace} {r['uid']} {side}_pkts {r[f'fm.{side}_pkts']} - {sub} != {k[f'{side}_pkts']}")
            if not sub and not r[f"fm.{side}_truncated"]:
                check(r[f"fm.{side}_bytes"] == k[f"{side}_ip_bytes"], f"{trace} {r['uid']} {side}_bytes")
        check(r.get("fm.duration") == k.get("duration"), f"{trace} {r['uid']} duration {r.get('fm.duration')} != conn.log {k.get('duration')}")
        check(abs(r["ts"] - k["ts"]) < 1e-6, f"{trace} {r['uid']} ts {r['ts']} != {k['ts']}")
        if trace == "trunc.pcap":
            check((r["fm.orig_truncated"], r["fm.resp_truncated"]) == ((3, 3) if icmp else (1, 1)), f"{trace} truncated counts")
        if trace == "exthdr.pcap" and k.get("proto") == "tcp":
            check((r["fm.orig_payload"], r["fm.resp_payload"]) == (100, 200),
                  f"{trace} {r['uid']} payload {r['fm.orig_payload']}/{r['fm.resp_payload']}")

# Bad checksums: Zeek (default settings) skips them, the plugin counts them and says so.
conn, fm = run("badsum.pcap", ignore_checksums=False)
r, k = fm[0], conn[0]
for side in ("orig", "resp"):
    check(r[f"fm.{side}_pkts"] - r[f"fm.{side}_skipped"] == k[f"{side}_pkts"], f"badsum {side} pkts-skipped")
    check(r[f"fm.{side}_skip_badsum"] == 1, f"badsum {side} badsum count {r[f'fm.{side}_skip_badsum']}")

# Times are exact integer microseconds: every gap is a whole number of them.
conn, fm = run("flowdef.pcap")
for r in fm:
    for key in ("iat_total", "iat_min", "iat_max", "orig_iat_min", "resp_iat_max"):
        v = r["fm." + key] * 1e6
        check(abs(v - round(v)) < 1e-6, f"flowdef {key} not whole microseconds: {v}")

# Bulk columns never change meaning: counts always, averages only with the setting.
# Profile and knobs, recorded in flowmeter_config.log
_, base = run("flowdef.pcap")
_, zf = run("flowdef.pcap", extra=("FlowMeter::profile=zeek-flowmeter",))
keyf = lambda r: (r["fm.start"], r["fm.orig_pkts"], r["fm.resp_pkts"], r["fm.orig_bytes"], r["fm.resp_bytes"])
b, z = {keyf(r): r for r in base}, {keyf(r): r for r in zf}
check(set(b) == set(z), "profile run has different connections")
check(all("fm.orig_bulk_pkts_avg" not in r for r in base), "default run writes bulk average columns")
check(all("fm.orig_bulk_pkts_avg" in r and "fm.resp_bulk_bytes_avg" in r for r in zf), "profile run lacks bulk average columns")
check(all(isinstance(r["fm.orig_bulk_pkts"], int) and isinstance(r["fm.orig_bulk_periods"], int) for r in base + zf), "bulk totals not counts")
for u in b:
    for key in ("iat_total", "orig_iat_max"):
        check(abs(z[u]["fm." + key] - b[u]["fm." + key] * 1e6) < 1e-3 * max(1, z[u]["fm." + key]), f"profile {key} not in microseconds")
    check(b[u].get("fm.duration") == z[u].get("fm.duration"), "profile must not change duration units")
_, c0 = run("other.pcap")
_, c1 = run("other.pcap", extra=("FlowMeter::icmp_header_as_payload=T",))
i0 = [r for r in c0 if r["fm.orig_header"] == 8]
i1 = [r for r in c1 if r["fm.orig_header"] == 0 and r["fm.orig_payload"] == 12]
check(len(i0) == 1 and len(i1) == 1, f"icmp knob: {len(i0)} default rows with header 8, {len(i1)} knob rows with payload 12")

# Knobs on knobs.pcap: out-of-order UDP, two TCP bulk periods, IPv4 echo and unreachable
bykind = lambda rows, c: {(k["proto"], k["id.orig_h"]): r for r, k in rows}
def knob_rows(extra=()):
    c, f = run("knobs.pcap", extra=extra)
    cm = {r["uid"]: r for r in c}
    out = {}
    for r in f:
        k = cm[r["uid"]]
        out[(k["proto"], k["id.orig_h"])] = r
    return out
kd, kz = knob_rows(), knob_rows(("FlowMeter::profile=zeek-flowmeter",))
u, uz = kd[("udp", "10.4.1.1")], kz[("udp", "10.4.1.1")]
check(u["fm.iat_min"] < 0 and abs(uz["fm.iat_min"] - abs(u["fm.iat_min"]) * 1e6) < 1e-3, "abs_gap: negative gap not made absolute")
check(u["fm.orig_min_seg"] == 0 and uz["fm.orig_min_seg"] == 8, f"min_header_all_protocols: {u['fm.orig_min_seg']} / {uz['fm.orig_min_seg']}")
tb, tz = kd[("tcp", "10.4.2.1")], kz[("tcp", "10.4.2.1")]
check(tb["fm.orig_bulk_periods"] == 2 and tb["fm.orig_bulk_pkts"] == 9, "bulk: expected 2 periods, 9 packets")
# profile requires 5 packets in a row (zeek-flowmeter): only the 5-packet burst counts, the 4-packet one does not
check((tz["fm.orig_bulk_periods"], tz["fm.orig_bulk_pkts"]) == (1, 5), f"profile bulk: {tz['fm.orig_bulk_periods']} periods {tz['fm.orig_bulk_pkts']} pkts")
check(abs(tz["fm.orig_bulk_pkts_avg"] - 5.0) < 1e-9 and abs(tz["fm.orig_bulk_bytes_avg"] - 500.0) < 1e-9, "bulk averages are not total/periods")
# default (min 4): both bursts, average = total / periods
_, bq = run("knobs.pcap", extra=("FlowMeter::bulk_per_period_avg=T",))
tq = [r for r in bq if r["fm.orig_bulk_periods"] == 2][0]
check(abs(tq["fm.orig_bulk_pkts_avg"] - 9 / 2) < 1e-9 and abs(tq["fm.orig_bulk_bytes_avg"] - 900 / 2) < 1e-9, "bulk averages are not total/periods")
e, ez = kd[("icmp", "10.4.3.1")], kz[("icmp", "10.4.3.1")]
x, xz = kd[("icmp", "10.4.4.2")], kz[("icmp", "10.4.4.2")]
check((e["fm.orig_header"], e["fm.orig_payload"]) == (8, 4), "icmp echo default must be header")
check((ez["fm.orig_header"], ez["fm.orig_payload"]) == (0, 12), "profile: echo 8 bytes must be payload")
check((kd[("icmp", "10.4.5.1")]["fm.orig_bulk_periods"], kd[("icmp", "10.4.5.1")]["fm.orig_bulk_pkts"]) == (1, 6), "bulk applies to ICMP echo trains too")
oc, of = run("other.pcap")
ocm = {r["uid"]: r for r in oc}
sctp = [r for r in of if ocm[r["uid"]]["ip_proto"] == 132 and r["fm.orig_pkts"] == 5][0]
check((sctp["fm.orig_bulk_periods"], sctp["fm.orig_bulk_pkts"]) == (1, 5), "bulk applies to SCTP (unknown transport)")
check((xz["fm.orig_header"], xz["fm.orig_payload"]) == (8, 4), "profile: unreachable must stay header")

print("FAILED" if fails else "ok", fails)
sys.exit(1 if fails else 0)
