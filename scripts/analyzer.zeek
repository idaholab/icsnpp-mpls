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
    const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}
