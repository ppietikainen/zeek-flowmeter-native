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

def run(trace, extra=()):
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o777)
        subprocess.run(["podman", "run", "--rm", "-v", f"{root}:/src:ro,z", "-v", f"{d}:/o:z", "-w", "/o",
                        "-e", "ZEEK_PLUGIN_PATH=/src/build", "--entrypoint", "zeek", img, "-C", "-r",
                        f"/src/testing/traces/{trace}", "Flow::Meter", "LogAscii::use_json=T", *extra],
                       check=True, capture_output=True)
        rd = lambda n: [json.loads(l) for l in open(f"{d}/{n}.log")]
        return rd("conn"), rd("flowmeter")

def check(ok, msg):
    global fails
    if not ok:
        fails += 1
        print("FAIL", msg)

for trace in ("flowdef.pcap", "flowdef-b.pcap", "exthdr.pcap"):
    conn, fm = run(trace)
    c = {r["uid"]: r for r in conn}
    check(len(fm) == len(conn), f"{trace}: {len(fm)} flowmeter rows vs {len(conn)} conn rows")
    for r in fm:
        k = c[r["uid"]]
        for mine, theirs in (("orig_pkts", "orig_pkts"), ("resp_pkts", "resp_pkts"),
                             ("orig_bytes", "orig_ip_bytes"), ("resp_bytes", "resp_ip_bytes")):
            check(r["s." + mine] == k[theirs], f"{trace} {r['uid']} {mine} {r['s.'+mine]} != {k[theirs]}")
        check(abs(r["ts"] - k["ts"]) < 1e-6, f"{trace} {r['uid']} ts {r['ts']} != {k['ts']}")
        if trace == "exthdr.pcap" and k.get("proto") == "tcp":
            check((r["s.orig_payload"], r["s.resp_payload"]) == (100, 200),
                  f"{trace} {r['uid']} payload {r['s.orig_payload']}/{r['s.resp_payload']}")

print("FAILED" if fails else "ok", fails)
sys.exit(1 if fails else 0)
