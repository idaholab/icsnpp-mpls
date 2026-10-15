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
		ts				: time  &log; # Unique ID to tie multiple headers 
		labels			: vector of count &log;  # Identifier used to make forwarding decisions
		experimentals	: vector of count &log;  # Used for Quality of Service (QoS) and traffic prioritization.
		bottom_of_stack : vector of bool  &log;  # Indicates whether this label is the last in the stack
		time_to_live	: vector of count &log;  
	};
}
