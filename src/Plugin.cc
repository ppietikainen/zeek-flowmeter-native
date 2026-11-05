#include "Plugin.h"

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "FlowStats.h"
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

using namespace zeek::plugin::Flow_Meter;

static zeek::EventHandlerPtr flow_done;
static zeek::RecordTypePtr stats_type;
static double activity_timeout = 5.0;  // seconds, CIC's default

namespace {

class Tap final : public zeek::packet_analysis::TapAnalyzer {
public:
    explicit Tap(zeek::Connection* c) : conn(c) {}

    void TapPacket(const zeek::Packet& pkt, zeek::packet_analysis::PacketAction,
                   zeek::packet_analysis::SkipReason) override {
        const auto& ip = pkt.ip_hdr;
        if ( ! ip )
            return;
        double t = pkt.time;
        Dir& d = f.d[pkt.is_orig ? 0 : 1];
        uint32_t total = ip->TotalLen();
        uint32_t hdr = ip->HdrLen();
        uint32_t l4 = ip->PayloadLen();
        uint32_t l4hdr = 0;
        uint8_t flags = 0;
        uint16_t win = 0;

        if ( ip->NextProto() == IPPROTO_TCP && l4 >= sizeof(tcphdr) ) {
            const auto* th = reinterpret_cast<const tcphdr*>(ip->Payload());
            l4hdr = th->th_off * 4;
            flags = th->th_flags;
            win = ntohs(th->th_win);
        }
        else if ( ip->NextProto() == IPPROTO_UDP )
            l4hdr = 8;
        else if ( ip->NextProto() == IPPROTO_ICMP || ip->NextProto() == IPPROTO_ICMPV6 )
            l4hdr = 8;
        uint32_t payload = l4 > l4hdr ? l4 - l4hdr : 0;

        if ( f.first < 0 ) {
            f.first = t;
            f.active_start = t;
        }
        else {
            double gap = t - f.last;
            f.flow_iat.Add(gap);
            if ( gap > 1.0 )
                f.subflows++;
            if ( gap > activity_timeout ) {
                f.active.Add(f.last - f.active_start);
                f.idle.Add(gap);
                f.active_start = t;
            }
        }
        f.last = t;
        f.len.Add(total);

        if ( payload > 0 ) {
            Dir& o = f.d[pkt.is_orig ? 1 : 0];
            // The other side sending payload ends our candidate run.
            o.bulk_cnt_h = 0;
            if ( d.bulk_cnt_h == 0 || t - d.bulk_last > 1.0 ) {
                d.bulk_start = t;
                d.bulk_cnt_h = 1;
                d.bulk_size_h = payload;
            }
            else {
                d.bulk_cnt_h++;
                d.bulk_size_h += payload;
                if ( d.bulk_cnt_h == 4 ) {
                    d.bulk_states++;
                    d.bulk_pkts += 4;
                    d.bulk_bytes += d.bulk_size_h;
                    d.bulk_dur += t - d.bulk_start;
                }
                else if ( d.bulk_cnt_h > 4 ) {
                    d.bulk_pkts++;
                    d.bulk_bytes += payload;
                    d.bulk_dur += t - d.bulk_last;
                }
            }
            d.bulk_last = t;
        }

        if ( d.last >= 0 )
            d.iat.Add(t - d.last);
        d.last = t;
        d.pkts++;
        d.bytes += total;
        d.payload += payload;
        d.header += l4hdr;
        d.iphdr += hdr;
        d.len.Add(total);
        d.pay.Add(payload);
        if ( payload > 0 ) d.data_pkts++;
        if ( l4hdr && ip->NextProto() == IPPROTO_TCP ) {
            if ( d.min_seg == 0 || l4hdr < d.min_seg ) d.min_seg = l4hdr;
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

    void Done() override {
        if ( ! flow_done || ! stats_type || f.first < 0 )
            return;
        if ( f.active_start >= 0 )
            f.active.Add(f.last - f.active_start);
        auto r = zeek::make_intrusive<zeek::RecordVal>(stats_type);
        int i = 0;
        const int nf = stats_type->NumFields();
        auto cnt = [&](uint64_t v) { if ( i < nf ) r->Assign(i, zeek::val_mgr->Count(v)); i++; };
        auto dbl = [&](double v) { if ( i < nf ) r->Assign(i, zeek::make_intrusive<zeek::DoubleVal>(v)); i++; };
        auto ival = [&](double v) { if ( i < nf ) r->Assign(i, zeek::make_intrusive<zeek::IntervalVal>(v)); i++; };
        r->Assign(i++, zeek::make_intrusive<zeek::TimeVal>(f.first));
        ival(f.last - f.first);
        for ( int k = 0; k < 2; k++ ) {
            const Dir& d = f.d[k];
            cnt(d.pkts); cnt(d.bytes); cnt(d.payload); cnt(d.header);
            dbl(d.len.min); dbl(d.len.max); dbl(d.len.mean); dbl(d.len.Std());
            dbl(d.pay.min); dbl(d.pay.max); dbl(d.pay.mean); dbl(d.pay.Std());
            dbl(d.iat.sum); dbl(d.iat.min); dbl(d.iat.max); dbl(d.iat.mean); dbl(d.iat.Std());
            cnt(d.psh); cnt(d.urg); cnt(d.fin); cnt(d.syn); cnt(d.rst); cnt(d.ack); cnt(d.cwr); cnt(d.ece);
            cnt(d.data_pkts); cnt(d.min_seg); cnt(d.init_win);
            cnt(d.bulk_states); cnt(d.bulk_pkts); cnt(d.bulk_bytes); dbl(d.bulk_dur);
            dbl(d.pkts ? double(d.bytes - d.iphdr) / d.pkts : 0.0);
        }
        dbl(f.len.min); dbl(f.len.max); dbl(f.len.mean); dbl(f.len.Std()); dbl(f.len.Var());
        cnt(f.subflows);
        dbl(f.flow_iat.sum); dbl(f.flow_iat.min); dbl(f.flow_iat.max); dbl(f.flow_iat.mean); dbl(f.flow_iat.Std());
        cnt(f.active.n); dbl(f.active.min); dbl(f.active.max); dbl(f.active.mean); dbl(f.active.Std());
        cnt(f.idle.n); dbl(f.idle.min); dbl(f.idle.max); dbl(f.idle.mean); dbl(f.idle.Std());

        if ( i != stats_type->NumFields() ) {
            zeek::reporter->InternalWarning("FlowMeter: %d values for %d fields", i, stats_type->NumFields());
            return;
        }
        zeek::event_mgr.Enqueue(flow_done, zeek::make_intrusive<zeek::StringVal>(conn->GetUID().Base62("C")),
                                std::move(r));
    }

private:
    zeek::Connection* conn;
    Flow f;
};

} // namespace

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Flow::Meter";
    config.description = "Per-connection flow statistics (CICFlowMeter-style features)";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
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
    if ( auto id = zeek::detail::global_scope()->Find("FlowMeter::activity_timeout"); id && id->GetVal() )
        activity_timeout = id->GetVal()->AsInterval();
}

void Plugin::HookSetupAnalyzerTree(zeek::Connection* conn) {
    if ( ! stats_type )
        return;
    if ( auto* a = conn->GetSessionAdapter() )
        a->AddTapAnalyzer(std::make_unique<Tap>(conn));
}
