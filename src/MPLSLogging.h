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

#include <zeek/iosource/Packet.h>
#include <zeek/packet_analysis/Analyzer.h>

namespace zeek::packet_analysis::MPLSLogger {

class MPLSLogger : public zeek::packet_analysis::Analyzer {
public:
    MPLSLogger();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<MPLSLogger>(); }
};

}
