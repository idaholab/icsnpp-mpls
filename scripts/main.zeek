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
    redef enum Log::ID += { LOG_HEADER };

    global log_policy_mpls_header: Log::PolicyHook;

    ## Raised by the packet analyzer for every MPLS packet.
    global mpls_header: event(h: MPLSLogger::MPLS_Header);

    ## Raised by the logging framework for every mpls_header.log record.
    global log_mpls_header: event(rec: MPLSLogger::MPLS_Header);

    ## Work out what follows the bottom label (IP, Ethernet pseudowire with
    ## or without a control word, or an associated channel) instead of
    ## always handing it to PacketAnalyzer::MPLSLOGGER::default_analyzer.
    const detect_payload: bool = T &redef;

    ## Label stack entries beyond this depth are skipped, not recorded.
    const max_label_stack_depth: count = 16 &redef;

    ## Write one record per MPLS packet instead of summarizing. Expect
    ## mpls_header.log to approach the packet count of the link.
    const log_every_packet: bool = F &redef;

    ## How long identical headers (same connection, direction, link-layer
    ## addresses, VLANs, label stack, and payload type) accumulate before one summary
    ## record is written.
    const summary_interval: interval = 1 min &redef;
}

global write_summary: function(t: table[string] of MPLS_Header, idx: string): interval;

global summaries: table[string] of MPLS_Header
    &create_expire=summary_interval &expire_func=write_summary;

function write_summary(t: table[string] of MPLS_Header, idx: string): interval
    {
    Log::write(LOG_HEADER, t[idx]);
    return 0 secs;
    }

function summary_key(h: MPLS_Header): string
    {
    return cat(h?$uid ? h$uid : "-", "|",
               h?$is_orig ? cat(h$is_orig) : "-", "|",
               h?$src_l2_addr ? h$src_l2_addr : "-", "|",
               h?$dst_l2_addr ? h$dst_l2_addr : "-", "|",
               h?$vlan ? cat(h$vlan) : "-", "|",
               h?$inner_vlan ? cat(h$inner_vlan) : "-", "|",
               h$labels, "|", h$traffic_class, "|", h$time_to_live, "|",
               h?$payload ? h$payload : "-");
    }

event zeek_init() &priority=5
    {
    Log::create_stream(MPLSLogger::LOG_HEADER, [$columns=MPLS_Header,
                                                $ev=log_mpls_header,
                                                $path="mpls_header",
                                                $policy=log_policy_mpls_header]);
    }

event MPLSLogger::mpls_header(h: MPLS_Header)
    {
    if ( log_every_packet )
        {
        Log::write(LOG_HEADER, h);
        return;
        }

    local k = summary_key(h);

    if ( k in summaries )
        {
        local s = summaries[k];
        ++s$packets;
        s$last_ts = h$ts;
        }
    else
        summaries[k] = h;
    }

event zeek_done()
    {
    for ( k, s in summaries )
        Log::write(LOG_HEADER, s);

    # Expiration doesn't fire for cleared entries, so nothing is written twice.
    clear_table(summaries);
    }
