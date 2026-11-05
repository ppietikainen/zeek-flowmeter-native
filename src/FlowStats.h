#pragma once

#include <cmath>
#include <cstdint>

namespace zeek::plugin::Flow_Meter {

// Running count/min/max/mean/variance (Welford); sample std (n-1), as zeek-flowmeter and CIC.
struct Running {
    uint64_t n = 0;
    double min = 0, max = 0, mean = 0, m2 = 0, sum = 0;

    void Add(double x) {
        if ( n == 0 )
            min = max = x;
        else {
            if ( x < min ) min = x;
            if ( x > max ) max = x;
        }
        n++;
        sum += x;
        double d = x - mean;
        mean += d / n;
        m2 += d * (x - mean);
    }
    double Std() const { return n > 1 ? std::sqrt(m2 / (n - 1)) : 0.0; }
    double Var() const { return n > 1 ? m2 / (n - 1) : 0.0; }
};

// Per direction. Lengths are IP-layer: total IP length, and L4 payload bytes.
struct Dir {
    uint64_t pkts = 0, bytes = 0, payload = 0, header = 0;
    Running len;        // IP total length per packet
    Running pay;        // transport payload bytes per packet (zeros included)
    Running iat;        // gap to previous packet in this direction, seconds
    double last = -1;
    uint64_t psh = 0, urg = 0, fin = 0, syn = 0, rst = 0, ack = 0, cwr = 0, ece = 0;
    uint64_t data_pkts = 0;      // packets with L4 payload > 0
    uint32_t min_seg = 0;        // min TCP header length seen
    bool have_win = false;
    uint32_t init_win = 0;       // window of the first packet in this direction
    // Bulk transfer (CIC rules): >= 4 payload packets, each within 1 s of the
    // previous one, with no payload packet from the other side in between.
    double bulk_start = 0, bulk_last = 0;
    uint64_t bulk_cnt_h = 0, bulk_size_h = 0;       // current candidate run
    uint64_t bulk_states = 0, bulk_pkts = 0, bulk_bytes = 0;
    double bulk_dur = 0;
};

struct Flow {
    Dir d[2];                    // 0 = orig, 1 = resp
    double first = -1, last = -1;
    Running flow_iat;
    // Active/idle: a gap above the activity timeout ends an active period.
    Running active, idle;
    double active_start = -1;
    Running len;                 // IP total length, both directions
    uint64_t subflows = 1;       // 1 + gaps above the subflow threshold (1 s)
};

} // namespace zeek::plugin::Flow_Meter
