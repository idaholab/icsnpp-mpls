# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - MPLS
##
## This file defines the Zeek script-layer logging and packet-analyzer
## registration for the ICSNPP MPLS parser.
##
## Melanie Pierce, Idaho National Lab, November 2026
## melanie.pierce@inl.gov
##
################################################################################

module MPLSLogger;

export {
    redef enum Log::ID += {LOG_HEADER};
    global log_policy_mpls_header: Log::PolicyHook;
    global log_mpls_header: event (rec: MPLSLogger::MPLS_Header);
    global log_mpls_header_stream: event (rec: MPLSLogger::MPLS_Header);
}

event zeek_init() {
    # Untagged MPLS
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8847, PacketAnalyzer::ANALYZER_MPLSLOGGER);

    # VLAN-tagged MPLS
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, 0x8847, PacketAnalyzer::ANALYZER_MPLSLOGGER);

    Log::create_stream(MPLSLogger::LOG_HEADER, [$columns=MPLS_Header,
                                                $ev=log_mpls_header_stream,
                                                $path="mpls_header",
                                                $policy=log_policy_mpls_header]);
}

# Fired from C++ for each MPLS packet - write to log
event log_mpls_header(header: MPLS_Header) {
    Log::write(LOG_HEADER, header);
}

# Fired by the log framework for each record - add filtering logic here if needed
event log_mpls_header_stream(header: MPLS_Header) {
}
