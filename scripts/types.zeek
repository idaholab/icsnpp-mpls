# Copyright 2026, Battelle Energy Alliance, LLC. All Rights Reserved.

################################################################################
##
## ICSNPP - MPLS
##
## This file defines the Zeek record used to log MPLS label stacks.
##
## Melanie Pierce, Idaho National Lab, November 2026
## melanie.pierce@inl.gov
##
################################################################################

module MPLSLogger;

export {
    type MPLS_Header: record {
        ## Time of the first packet summarized by this record.
        ts: time &log;
        ## UID of the connection carried in the MPLS payload, if any.
        uid: string &log &optional;
        ## 4-tuple of that connection.
        id: conn_id &log &optional;
        ## True if the packet(s) traveled from the connection's originator.
        is_orig: bool &log &optional;
        ## Link-layer source address of the frame carrying the label stack.
        src_l2_addr: string &log &optional;
        ## Link-layer destination address of the frame carrying the label stack.
        dst_l2_addr: string &log &optional;
        ## Outer 802.1Q VLAN ID, if present.
        vlan: int &log &optional;
        ## Inner 802.1Q VLAN ID (QinQ), if present.
        inner_vlan: int &log &optional;
        ## MPLS labels, outermost first. The last entry is the one that
        ## carried the bottom-of-stack flag; records are only written for
        ## stacks that reached it.
        labels: vector of count &log;
        ## Traffic Class bits for each label (called EXP before RFC 5462).
        traffic_class: vector of count &log;
        ## TTL for each label.
        time_to_live: vector of count &log;
        ## What followed the bottom label: ipv4, ipv6, ethernet,
        ## ethernet+cw (pseudowire control word), ach-ipv4, ach-ipv6,
        ## ach (associated channel carrying something other than IP), or
        ## unknown. Unset when MPLSLogger::detect_payload is F.
        payload: string &log &optional;
        ## Number of packets summarized by this record.
        packets: count &log &default=1;
        ## Time of the last packet summarized by this record.
        last_ts: time &log &optional;
    };
}
