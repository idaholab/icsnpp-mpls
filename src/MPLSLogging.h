// Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

////////////////////////////////////////////////////////////////////////////////
//
// ICSNPP - MPLS
//
// This file declares the Zeek packet analyzer for MPLS label stacks.
//
// Melanie Pierce, Idaho National Lab, November 2026
// melanie.pierce@inl.gov
//
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <zeek/EventHandler.h>
#include <zeek/Type.h>
#include <zeek/iosource/Packet.h>
#include <zeek/packet_analysis/Analyzer.h>

namespace zeek::packet_analysis::MPLSLogger {

class MPLSLogger : public zeek::packet_analysis::Analyzer {
public:
    MPLSLogger();
    ~MPLSLogger() override = default;

    void Initialize() override;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    // Dispatch identifiers for the payload after the label stack. They are
    // registered against ANALYZER_MPLSLOGGER in scripts/analyzer.zeek.
    static constexpr uint32_t PAYLOAD_IPV4 = 0x0800;
    static constexpr uint32_t PAYLOAD_IPV6 = 0x86DD;
    static constexpr uint32_t PAYLOAD_ETHERNET = 0x6558; // Transparent Ethernet Bridging

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<MPLSLogger>(); }

private:
    // Outcome of looking at the bytes after the bottom label.
    enum class Forward { Default, Identifier, None };

    // Works out what follows the label stack. May advance data/len past a
    // pseudowire control word or associated channel header. Sets kind to a
    // short name for the log and identifier when the result is Identifier.
    Forward ClassifyPayload(uint32_t bottom_label, const uint8_t*& data, size_t& len, const char*& kind,
                            uint32_t& identifier) const;

    // Resolved once in Initialize() rather than on every packet.
    zeek::RecordTypePtr header_type;
    zeek::VectorTypePtr count_vec_type;
    zeek::EventHandlerPtr mpls_header_event;
    uint64_t max_depth = 16;
    bool detect_payload = true;

    int ts_off = -1;
    int uid_off = -1;
    int id_off = -1;
    int is_orig_off = -1;
    int src_l2_off = -1;
    int dst_l2_off = -1;
    int vlan_off = -1;
    int inner_vlan_off = -1;
    int labels_off = -1;
    int tc_off = -1;
    int ttls_off = -1;
    int payload_off = -1;
};

} // namespace zeek::packet_analysis::MPLSLogger
