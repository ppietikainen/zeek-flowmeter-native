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

for trace in ("flowdef.pcap", "flowdef-b.pcap", "exthdr.pcap", "other.pcap", "flip.pcap", "flip2.pcap", "trunc.pcap"):
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

print("FAILED" if fails else "ok", fails)
sys.exit(1 if fails else 0)
