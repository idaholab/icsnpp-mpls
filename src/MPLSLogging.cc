// Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

////////////////////////////////////////////////////////////////////////////////
//
// ICSNPP - MPLS
//
// This file implements the Zeek packet analyzer for MPLS label stacks.
//
// Melanie Pierce, Idaho National Lab, November 2026
// melanie.pierce@inl.gov
//
////////////////////////////////////////////////////////////////////////////////

#include "MPLSLogging.h"

#include <cstdio>
#include <optional>
#include <string>
#include <type_traits>

#include <zeek/Conn.h>
#include <zeek/Event.h>
#include <zeek/EventRegistry.h>
#include <zeek/ID.h>
#include <zeek/Reporter.h>
#include <zeek/Val.h>
#include <zeek/session/Session.h>

using namespace zeek::packet_analysis::MPLSLogger;

namespace {

constexpr size_t MPLS_LSE_LEN = 4; // one label stack entry (RFC 3032)

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

// A header that's internally consistent with the bytes we have.
bool plausible_ipv4(const uint8_t* d, size_t len) {
    if ( len < 20 || (d[0] >> 4) != 4 )
        return false;

    const size_t hdr_len = static_cast<size_t>(d[0] & 0x0F) * 4;
    const size_t total_len = be16(d + 2);
    return hdr_len >= 20 && hdr_len <= total_len && total_len <= len;
}

bool plausible_ipv6(const uint8_t* d, size_t len) {
    if ( len < 40 || (d[0] >> 4) != 6 )
        return false;

    return 40 + static_cast<size_t>(be16(d + 4)) <= len;
}

// 0: can't be an Ethernet frame. 1: could be. 2: carries an EtherType we
// recognize. Used to break the tie between "control word, then Ethernet"
// and "Ethernet whose destination MAC starts with a zero nibble" (GOOSE and
// SV multicast addresses start with 01:0c:cd).
int ethernet_score(const uint8_t* d, size_t len) {
    if ( len < 14 )
        return 0;

    const uint16_t type_or_len = be16(d + 12);

    // 802.3 length field (LLC frames such as STP and CDP).
    if ( type_or_len <= 1500 )
        return (type_or_len >= 3 && type_or_len <= len - 14) ? 1 : 0;

    if ( type_or_len < 0x0600 )
        return 0;

    switch ( type_or_len ) {
        case 0x0800: // IPv4
        case 0x0806: // ARP
        case 0x86DD: // IPv6
        case 0x8100: // 802.1Q
        case 0x88A8: // 802.1ad
        case 0x9100: // QinQ (legacy)
        case 0x8847: // MPLS unicast
        case 0x8848: // MPLS multicast
        case 0x8863: // PPPoE discovery
        case 0x8864: // PPPoE session
        case 0x8809: // slow protocols (LACP)
        case 0x88CC: // LLDP
        case 0x88E5: // MACsec
        case 0x88F7: // PTP
        case 0x88B8: // IEC 61850 GOOSE
        case 0x88B9: // IEC 61850 GSE management
        case 0x88BA: // IEC 61850 sampled values
        case 0x8892: // PROFINET
        case 0x88A4: // EtherCAT
        case 0x88E3: // MRP
        case 0x22F0: // AVTP
            return 2;
        default:
            return 1;
    }
}

// Packet::vlan and Packet::inner_vlan are uint32_t (0 meaning untagged)
// before Zeek 8.2 and std::optional<VlanTag> from 8.2 on.
template<typename T>
std::optional<int64_t> vlan_id(const T& v) {
    if constexpr ( std::is_integral_v<T> ) {
        if ( v )
            return static_cast<int64_t>(v);
    }
    else {
        if ( v )
            return static_cast<int64_t>(v->id);
    }

    return std::nullopt;
}

std::string format_mac(const u_char* m) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return std::string(buf);
}

} // namespace

MPLSLogger::MPLSLogger() : zeek::packet_analysis::Analyzer("MPLSLogger") {}

void MPLSLogger::Initialize() {
    // Loads default_analyzer and friends from PacketAnalyzer::MPLSLOGGER.
    Analyzer::Initialize();

    header_type = zeek::id::find_type<zeek::RecordType>("MPLSLogger::MPLS_Header");
    mpls_header_event = zeek::event_registry->Lookup("MPLSLogger::mpls_header");
    max_depth = zeek::id::find_val("MPLSLogger::max_label_stack_depth")->AsCount();
    detect_payload = zeek::id::find_val("MPLSLogger::detect_payload")->AsBool();

    auto field = [this](const char* name) {
        int off = header_type->FieldOffset(name);
        if ( off < 0 )
            zeek::reporter->FatalError("MPLSLogger::MPLS_Header is missing field '%s'", name);
        return off;
    };

    ts_off = field("ts");
    uid_off = field("uid");
    id_off = field("id");
    is_orig_off = field("is_orig");
    src_l2_off = field("src_l2_addr");
    dst_l2_off = field("dst_l2_addr");
    vlan_off = field("vlan");
    inner_vlan_off = field("inner_vlan");
    labels_off = field("labels");
    tc_off = field("traffic_class");
    ttls_off = field("time_to_live");
    payload_off = field("payload");

    count_vec_type = zeek::cast_intrusive<zeek::VectorType>(header_type->GetFieldType(labels_off));
}

MPLSLogger::Forward MPLSLogger::ClassifyPayload(uint32_t bottom_label, const uint8_t*& data, size_t& len,
                                                const char*& kind, uint32_t& identifier) const {
    kind = "unknown";

    if ( len == 0 )
        return Forward::Default;

    // Explicit NULL labels say what's underneath (RFC 3032).
    if ( bottom_label == 0 ) {
        kind = "ipv4";
        identifier = PAYLOAD_IPV4;
        return Forward::Identifier;
    }

    if ( bottom_label == 2 ) {
        kind = "ipv6";
        identifier = PAYLOAD_IPV6;
        return Forward::Identifier;
    }

    const uint8_t nibble = data[0] >> 4;

    // Associated channel header (RFC 4385, RFC 5586): pseudowire VCCV, or
    // G-ACh after a GAL (label 13). 0001 | version | reserved | channel type.
    if ( nibble == 1 ) {
        if ( len < 4 )
            return Forward::Default;

        const uint16_t channel = be16(data + 2);
        data += 4;
        len -= 4;

        if ( channel == 0x0021 ) {
            kind = "ach-ipv4";
            identifier = PAYLOAD_IPV4;
            return Forward::Identifier;
        }

        if ( channel == 0x0057 ) {
            kind = "ach-ipv6";
            identifier = PAYLOAD_IPV6;
            return Forward::Identifier;
        }

        // BFD, MPLS-TP OAM, and so on. Nothing downstream would parse it.
        kind = "ach";
        return Forward::None;
    }

    if ( nibble == 4 && plausible_ipv4(data, len) ) {
        kind = "ipv4";
        identifier = PAYLOAD_IPV4;
        return Forward::Identifier;
    }

    if ( nibble == 6 && plausible_ipv6(data, len) ) {
        kind = "ipv6";
        identifier = PAYLOAD_IPV6;
        return Forward::Identifier;
    }

    // Ethernet pseudowire. A control word (RFC 4385) also starts with 0000,
    // so for a zero nibble compare both readings and prefer the control word
    // when they tie.
    const int without_cw = ethernet_score(data, len);
    const int with_cw = (nibble == 0 && len >= 4) ? ethernet_score(data + 4, len - 4) : 0;

    if ( with_cw > 0 && with_cw >= without_cw ) {
        data += 4;
        len -= 4;
        kind = "ethernet+cw";
        identifier = PAYLOAD_ETHERNET;
        return Forward::Identifier;
    }

    if ( without_cw > 0 ) {
        kind = "ethernet";
        identifier = PAYLOAD_ETHERNET;
        return Forward::Identifier;
    }

    return Forward::Default;
}

bool MPLSLogger::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    // Only build script-layer values when a handler will consume them.
    const bool want_event = static_cast<bool>(mpls_header_event);

    zeek::VectorValPtr labels;
    zeek::VectorValPtr tcs;
    zeek::VectorValPtr ttls;

    if ( want_event ) {
        labels = zeek::make_intrusive<zeek::VectorVal>(count_vec_type);
        tcs = zeek::make_intrusive<zeek::VectorVal>(count_vec_type);
        ttls = zeek::make_intrusive<zeek::VectorVal>(count_vec_type);
    }

    bool end_of_stack = false;
    uint64_t depth = 0;
    uint32_t bottom_label = 0;

    while ( ! end_of_stack ) {
        if ( len < MPLS_LSE_LEN ) {
            Weird("truncated_link_header", packet);
            return false;
        }

        const uint32_t lse = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
                             (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);

        const uint32_t label = lse >> 12; // 20 bits
        const uint32_t tc = (lse >> 9) & 0x7;
        end_of_stack = ((lse >> 8) & 0x1) != 0;
        const uint32_t ttl = lse & 0xFF;
        bottom_label = label;

        // Keep walking the stack regardless so the payload offset is right,
        // but don't let a crafted packet turn into an enormous log record.
        if ( want_event && depth < max_depth ) {
            labels->Assign(labels->Size(), zeek::val_mgr->Count(label));
            tcs->Assign(tcs->Size(), zeek::val_mgr->Count(tc));
            ttls->Assign(ttls->Size(), zeek::val_mgr->Count(ttl));
        }

        ++depth;
        data += MPLS_LSE_LEN;
        len -= MPLS_LSE_LEN;
    }

    if ( depth > max_depth )
        Weird("excessive_mpls_label_stack", packet);

    Forward how = Forward::Default;
    const char* payload_kind = nullptr;
    uint32_t identifier = 0;

    if ( detect_payload )
        how = ClassifyPayload(bottom_label, data, len, payload_kind, identifier);

    zeek::RecordValPtr rec;

    if ( want_event ) {
        rec = zeek::make_intrusive<zeek::RecordVal>(header_type);
        rec->Assign(ts_off, zeek::make_intrusive<zeek::TimeVal>(packet->time));

        // Capture the link layer now. If the payload gets forwarded to the
        // Ethernet analyzer (pseudowires), l2_src/l2_dst get overwritten with
        // the inner frame's addresses.
        if ( packet->l2_src )
            rec->Assign(src_l2_off, zeek::make_intrusive<zeek::StringVal>(format_mac(packet->l2_src)));
        if ( packet->l2_dst )
            rec->Assign(dst_l2_off, zeek::make_intrusive<zeek::StringVal>(format_mac(packet->l2_dst)));
        if ( auto vlan = vlan_id(packet->vlan) )
            rec->Assign(vlan_off, zeek::val_mgr->Int(*vlan));
        if ( auto inner_vlan = vlan_id(packet->inner_vlan) )
            rec->Assign(inner_vlan_off, zeek::val_mgr->Int(*inner_vlan));

        rec->Assign(labels_off, labels);
        rec->Assign(tc_off, tcs);
        rec->Assign(ttls_off, ttls);

        if ( payload_kind )
            rec->Assign(payload_off, zeek::make_intrusive<zeek::StringVal>(payload_kind));
    }

    // Hide any session an outer layer attached (MPLS inside a UDP tunnel, for
    // example) so that whatever is in packet->session after forwarding was
    // set by this label stack's own payload.
    auto* outer_session = packet->session;
    packet->session = nullptr;

    // RFC 3032 doesn't encode the payload protocol. Use what
    // ClassifyPayload() found, or the configured default analyzer.
    bool forwarded = true;

    if ( how == Forward::Identifier )
        forwarded = ForwardPacket(len, data, packet, identifier);
    else if ( how == Forward::Default )
        forwarded = ForwardPacket(len, data, packet);

    if ( rec ) {
        // Set by IPBasedAnalyzer when the payload produced or matched a
        // connection. The Connection outlives this call: removal is deferred
        // behind connection_state_remove, which holds a reference.
        if ( auto* conn = dynamic_cast<zeek::Connection*>(packet->session) ) {
            rec->Assign(uid_off, zeek::make_intrusive<zeek::StringVal>(conn->GetUID().Base62("C")));
            rec->Assign(id_off, conn->GetVal()->GetField("id"));
            rec->Assign(is_orig_off, zeek::val_mgr->Bool(packet->is_orig));
        }

        zeek::event_mgr.Enqueue(mpls_header_event, zeek::Args{std::move(rec)});
    }

    if ( ! packet->session )
        packet->session = outer_session;

    return forwarded;
}
