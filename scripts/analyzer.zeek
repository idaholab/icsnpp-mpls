# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - MPLS
##
## This file defines the analyzer used for payloads following MPLS label stacks.
##
## Melanie Pierce, Idaho National Lab, November 2026
## melanie.pierce@inl.gov
##
################################################################################

module PacketAnalyzer::MPLSLOGGER;

export {
    ## Analyzer used for the payload after the MPLS label stack.
    ## Used when MPLSLogger::detect_payload is F, or when detection can't
    ## tell what follows the bottom label.
    const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

# Identifiers handed to ForwardPacket() by the payload detection in
# MPLSLogging.cc. They follow EtherType numbering; 0x6558 is Transparent
# Ethernet Bridging, the same value GRE uses for Ethernet payloads.
event zeek_init() &priority=20
    {
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_MPLSLOGGER, 0x0800, PacketAnalyzer::ANALYZER_IP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_MPLSLOGGER, 0x86DD, PacketAnalyzer::ANALYZER_IP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_MPLSLOGGER, 0x6558, PacketAnalyzer::ANALYZER_ETHERNET);
    }
