#include "Plugin.h"

#include <netinet/in.h>
#include <cmath>
#include <cstdlib>
#include <netinet/tcp.h>

#include "FlowStats.h"
#include "zeek/Conn.h"
#include "zeek/analyzer/Component.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

using namespace zeek::plugin::Flow_Meter;

static zeek::EventHandlerPtr flow_done;
static zeek::RecordTypePtr stats_type;
static double activity_timeout = 5.0;  // seconds, CIC's default
static double subflow_gap = 1.0;       // seconds
static double bulk_gap = 1.0;          // seconds
static uint64_t bulk_min_packets = 4;

// Resolved knobs (script record FlowMeter::settings), loaded when the first connection starts.
static struct {
    bool abs_gap = false, icmp_header_as_payload = false, icmp_echo_as_payload = false, min_header_all_protocols = false;
    bool time_microseconds = false, bulk_per_period_avg = false;
    bool loaded = false;
} cfg;

namespace {

class Meter {
public:
    // Statistics are kept per endpoint, A = sender of the first packet, B = the other one.
    // Zeek may flip originator and responder after packets were seen, so which endpoint is
    // the originator is decided only in Emit(), from the connection's final roles.
    // cap_ip: IP bytes present in the capture (UINT32_MAX if unknown).
    void Observe(int64_t t, const zeek::IP_Hdr* ip, uint32_t cap_ip, bool skipped = false, bool badsum = false) {
        uint32_t total = ip->TotalLen();
        uint8_t proto = ip->NextProto();
        uint16_t sport = 0;
        bool ports = (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && ip->PayloadLen() >= 4 && cap_ip >= ip->HdrLen() + 4;
        if ( ports ) {
            sport = *reinterpret_cast<const uint16_t*>(ip->Payload());  // network order
            has_ports = true;
        }
        int idx;
        if ( ! ep_set[0] || (ep_addr[0] == ip->SrcAddr() && ep_port[0] == sport) )
            idx = 0;
        else
            idx = 1;
        if ( ! ep_set[idx] ) {
            ep_set[idx] = true;
            ep_addr[idx] = ip->SrcAddr();
            ep_port[idx] = sport;
        }
        Dir& d = f.d[idx];
        if ( skipped ) d.skipped++;
        if ( badsum ) d.skip_badsum++;
        if ( cap_ip < total ) d.truncated++;
        uint32_t hdr = ip->HdrLen();
        uint32_t l4 = ip->PayloadLen();
        uint32_t l4hdr = 0;
        uint8_t flags = 0;
        uint16_t win = 0;

        if ( ip->NextProto() == IPPROTO_TCP && l4 >= sizeof(tcphdr) && cap_ip >= hdr + sizeof(tcphdr) ) {
            const auto* th = reinterpret_cast<const tcphdr*>(ip->Payload());
            l4hdr = th->th_off * 4;
            flags = th->th_flags;
            win = ntohs(th->th_win);
        }
        else if ( ip->NextProto() == IPPROTO_UDP )
            l4hdr = 8;
        else if ( ip->NextProto() == IPPROTO_ICMP || ip->NextProto() == IPPROTO_ICMPV6 ) {
            l4hdr = cfg.icmp_header_as_payload ? 0 : 8;
            // IPv4 echo request/reply: the 8 bytes count as payload (zeek-flowmeter profile)
            if ( cfg.icmp_echo_as_payload && ip->NextProto() == IPPROTO_ICMP && l4 >= 1 && cap_ip >= hdr + 1 ) {
                uint8_t type = ip->Payload()[0];
                if ( type == 0 || type == 8 )
                    l4hdr = 0;
            }
        }
        uint32_t payload = l4 > l4hdr ? l4 - l4hdr : 0;

        if ( f.first < 0 ) {
            f.first = t;
            f.active_start = t;
        }
        else {
            // Out of order input gives negative gaps; the default keeps them, the zeek-flowmeter
            // profile takes the absolute value.
            int64_t g = t - f.last;
            double gap = cfg.abs_gap ? std::llabs(g) : g;
            f.flow_iat.Add(gap);
            if ( gap > subflow_gap * 1e6 )
                f.subflows++;
            if ( gap > activity_timeout * 1e6 ) {
                f.active.Add(double(f.last - f.active_start));
                f.idle.Add(gap);
                f.active_start = t;
            }
        }
        f.last = t;
        f.len.Add(total);

        // Bulk transfer is a stream notion: TCP and UDP only, 0 for ICMP and other protocols.
        if ( payload > 0 && (proto == IPPROTO_TCP || proto == IPPROTO_UDP) ) {
            Dir& o = f.d[1 - idx];
            // The other side sending payload ends our candidate run.
            o.bulk_cnt_h = 0;
            if ( d.bulk_cnt_h == 0 || t - d.bulk_last > bulk_gap * 1e6 ) {
                d.bulk_start = t;
                d.bulk_cnt_h = 1;
                d.bulk_size_h = payload;
            }
            else {
                d.bulk_cnt_h++;
                d.bulk_size_h += payload;
                if ( d.bulk_cnt_h == bulk_min_packets ) {
                    d.bulk_states++;
                    d.bulk_pkts += bulk_min_packets;
                    d.bulk_bytes += d.bulk_size_h;
                    d.bulk_dur += double(t - d.bulk_start);
                }
                else if ( d.bulk_cnt_h > bulk_min_packets ) {
                    d.bulk_pkts++;
                    d.bulk_bytes += payload;
                    d.bulk_dur += double(t - d.bulk_last);
                }
            }
            d.bulk_last = t;
        }

        if ( d.last >= 0 ) {
            int64_t g = t - d.last;
            d.iat.Add(cfg.abs_gap ? double(std::llabs(g)) : double(g));
        }
        d.last = t;
        d.pkts++;
        d.bytes += total;
        d.payload += payload;
        d.header += l4hdr;
        d.len.Add(total);
        d.pay.Add(payload);
        if ( payload > 0 ) d.data_pkts++;
        if ( l4hdr && (ip->NextProto() == IPPROTO_TCP || cfg.min_header_all_protocols) )
            if ( d.min_seg == 0 || l4hdr < d.min_seg ) d.min_seg = l4hdr;
        if ( l4hdr && ip->NextProto() == IPPROTO_TCP ) {
            if ( ! d.have_win ) { d.have_win = true; d.init_win = win; }
            if ( flags & TH_FIN ) d.fin++;
            if ( flags & TH_SYN ) d.syn++;
            if ( flags & TH_RST ) d.rst++;
            if ( flags & TH_PUSH ) d.psh++;
            if ( flags & TH_ACK ) d.ack++;
            if ( flags & TH_URG ) d.urg++;
            if ( flags & 0x80 ) d.cwr++;
            if ( flags & 0x40 ) d.ece++;
        }
    }

    void Emit(zeek::Connection* conn) {
        if ( ! flow_done || ! stats_type || f.first < 0 )
            return;
        if ( f.active_start >= 0 )
            f.active.Add(double(f.last - f.active_start));
        auto r = zeek::make_intrusive<zeek::RecordVal>(stats_type);
        int i = 0;
        const int nf = stats_type->NumFields();
        auto cnt = [&](uint64_t v) { if ( i < nf ) r->Assign(i, zeek::val_mgr->Count(v)); i++; };
        auto dbl = [&](double v) { if ( i < nf ) r->Assign(i, zeek::make_intrusive<zeek::DoubleVal>(v)); i++; };
        auto ival = [&](double v) { if ( i < nf ) r->Assign(i, zeek::make_intrusive<zeek::IntervalVal>(v)); i++; };
        // Seconds as Zeek computes them from the timeval, so start equals conn.log's ts.
        r->Assign(i++, zeek::make_intrusive<zeek::TimeVal>(double(f.first / 1000000) + double(f.first % 1000000) / 1e6));
        // duration is Zeek's own (conn.log's), unset where Zeek writes none; span is the first
        // to last packet as this plugin saw them, signed with out of order timestamps.
        double zd = conn->LastTime() - conn->StartTime();
        if ( zd > 0 ) ival(zd); else i++;   // conn.log writes it only when positive
        ival(double(f.last - f.first) / 1e6);
        const double sc = cfg.time_microseconds ? 1.0 : 1e-6;   // internal times are microseconds
        auto rs = [&](const Running& x) { dbl(x.sum * sc); dbl(x.min * sc); dbl(x.max * sc); dbl(x.mean * sc); dbl(x.Std() * sc); };
        // The originator is the endpoint matching the connection's final originator.
        // ICMP and other protocols carry no ports (Zeek uses type/code), so only the address counts.
        auto is_orig_ep = [&](int e) {
            return ep_set[e] && ep_addr[e] == conn->OrigAddr() && (! has_ports || ep_port[e] == conn->OrigPort());
        };
        // Endpoint 0 is the originator if it matches; otherwise endpoint 1 is, seen or not.
        int orig_ep = is_orig_ep(0) ? 0 : 1;
        for ( int k = 0; k < 2; k++ ) {
            const Dir& d = f.d[k == 0 ? orig_ep : 1 - orig_ep];
            cnt(d.pkts); cnt(d.bytes); cnt(d.payload); cnt(d.header);
            dbl(d.len.min); dbl(d.len.max); dbl(d.len.mean); dbl(d.len.Std());
            dbl(d.pay.min); dbl(d.pay.max); dbl(d.pay.mean); dbl(d.pay.Std());
            rs(d.iat);
            cnt(d.psh); cnt(d.urg); cnt(d.fin); cnt(d.syn); cnt(d.rst); cnt(d.ack); cnt(d.cwr); cnt(d.ece);
            cnt(d.data_pkts); cnt(d.min_seg); cnt(d.init_win);
            cnt(d.bulk_states); cnt(d.bulk_pkts); cnt(d.bulk_bytes); dbl(d.bulk_dur * sc);
            // Averages per bulk period are separate columns, written only when asked for
            // (zeek-flowmeter profile); no column changes meaning with a setting.
            if ( cfg.bulk_per_period_avg ) {
                dbl(d.bulk_states ? double(d.bulk_pkts) / d.bulk_states : 0.0);
                dbl(d.bulk_states ? double(d.bulk_bytes) / d.bulk_states : 0.0);
            }
            else
                i += 2;
            cnt(d.skipped); cnt(d.skip_badsum); cnt(d.truncated);
        }
        dbl(f.len.min); dbl(f.len.max); dbl(f.len.mean); dbl(f.len.Std()); dbl(f.len.Var());
        cnt(f.subflows);
        rs(f.flow_iat);
        cnt(f.active.n); dbl(f.active.min * sc); dbl(f.active.max * sc); dbl(f.active.mean * sc); dbl(f.active.Std() * sc);
        cnt(f.idle.n); dbl(f.idle.min * sc); dbl(f.idle.max * sc); dbl(f.idle.mean * sc); dbl(f.idle.Std() * sc);

        if ( i != stats_type->NumFields() ) {
            zeek::reporter->InternalWarning("FlowMeter: %d values for %d fields", i, stats_type->NumFields());
            return;
        }
        zeek::event_mgr.Enqueue(flow_done, zeek::make_intrusive<zeek::StringVal>(conn->GetUID().Base62("C")),
                                std::move(r));
    }


private:
    Flow f;
    zeek::IPAddr ep_addr[2];
    uint16_t ep_port[2] = {0, 0};
    bool ep_set[2] = {false, false};
    bool has_ports = false;
};

class Tap final : public zeek::packet_analysis::TapAnalyzer {
public:
    explicit Tap(zeek::Connection* c) : conn(c) {}

    void TapPacket(const zeek::Packet& pkt, zeek::packet_analysis::PacketAction action,
                   zeek::packet_analysis::SkipReason reason) override {
        if ( pkt.ip_hdr ) {
            // IP bytes in the capture, when the IP header points into the captured data
            uint32_t cap_ip = UINT32_MAX;
            const u_char* start = pkt.ip_hdr->IP4_Hdr() ? reinterpret_cast<const u_char*>(pkt.ip_hdr->IP4_Hdr())
                                                         : reinterpret_cast<const u_char*>(pkt.ip_hdr->IP6_Hdr());
            const u_char* end = pkt.data + pkt.cap_len;
            if ( pkt.data && start >= pkt.data && start <= end )
                cap_ip = end - start;
            m.Observe(int64_t(pkt.ts.tv_sec) * 1000000 + pkt.ts.tv_usec, pkt.ip_hdr.get(), cap_ip, action == zeek::packet_analysis::PacketAction::Skip,
                      reason == zeek::packet_analysis::SkipReason::BadChecksum);
        }
    }

    void Done() override { m.Emit(conn); }

private:
    zeek::Connection* conn;
    Meter m;
};

// Zeek's tap never sees packets of unknown IP transports (ESP, OSPF, ...), but a
// child analyzer of the session does, as ConnSize shows.
class Child final : public zeek::analyzer::Analyzer {
public:
    explicit Child(zeek::Connection* c) : zeek::analyzer::Analyzer("FlowMeter", c) {}

    void Done() override {
        zeek::analyzer::Analyzer::Done();
        m.Emit(Conn());
    }

protected:
    void DeliverPacket(int, const u_char*, bool is_orig, uint64_t, const zeek::IP_Hdr* ip, int) override {
        if ( ip )
            m.Observe(std::llround(zeek::run_state::network_time * 1e6), ip, UINT32_MAX);
    }

private:
    Meter m;
};

} // namespace

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Flow::Meter";
    config.description = "Per-connection flow statistics (CICFlowMeter-style features)";
    int ma = 0, mi = 0, pa = 0;
    sscanf(FLOWMETER_VERSION, "%d.%d.%d", &ma, &mi, &pa);
    config.version.major = ma;
    config.version.minor = mi;
    config.version.patch = pa;
    // Registered so the child analyzer used for unknown IP transports has a tag.
    AddComponent(new zeek::analyzer::Component("FlowMeter", nullptr));
    EnableHook(zeek::plugin::HOOK_SETUP_ANALYZER_TREE);
    return config;
}

void Plugin::InitPostScript() {
    // Scripts may not be loaded (zeek -N, other script sets): stay inert then.
    auto type_id = zeek::detail::global_scope()->Find("FlowMeter::Stats");
    if ( ! type_id || ! type_id->IsType() )
        return;
    stats_type = zeek::cast_intrusive<zeek::RecordType>(type_id->GetType());
    flow_done = zeek::event_registry->Register("FlowMeter::flow_done");
    auto val = [](const char* name) -> zeek::ValPtr {
        auto id = zeek::detail::global_scope()->Find(name);
        return id ? id->GetVal() : nullptr;
    };
    if ( auto v = val("FlowMeter::activity_timeout") ) activity_timeout = v->AsInterval();
    if ( auto v = val("FlowMeter::subflow_gap") ) subflow_gap = v->AsInterval();
    if ( auto v = val("FlowMeter::bulk_gap") ) bulk_gap = v->AsInterval();
    if ( auto v = val("FlowMeter::bulk_min_packets") ) bulk_min_packets = v->AsCount();
}

void Plugin::HookSetupAnalyzerTree(zeek::Connection* conn) {
    if ( ! stats_type )
        return;
    if ( ! cfg.loaded ) {
        cfg.loaded = true;
        auto id = zeek::detail::global_scope()->Find("FlowMeter::settings");
        if ( id && id->GetVal() ) {
            auto rv = id->GetVal()->AsRecordVal();
            auto get = [&](const char* n) { int k = rv->GetType<zeek::RecordType>()->FieldOffset(n); return k >= 0 && rv->GetFieldAs<zeek::BoolVal>(k); };
            cfg.abs_gap = get("abs_gap");
            cfg.icmp_header_as_payload = get("icmp_header_as_payload");
            cfg.icmp_echo_as_payload = get("icmp_echo_as_payload");
            cfg.min_header_all_protocols = get("min_header_all_protocols");
            cfg.time_microseconds = get("time_microseconds");
            cfg.bulk_per_period_avg = get("bulk_per_period_avg");
        }
    }
    if ( auto* a = conn->GetSessionAdapter() ) {
        if ( strcmp(a->GetAnalyzerName(), "UNKNOWN_IP_TRANSPORT") == 0 )
            a->AddChildAnalyzer(new Child(conn));
        else
            a->AddTapAnalyzer(std::make_unique<Tap>(conn));
    }
}
