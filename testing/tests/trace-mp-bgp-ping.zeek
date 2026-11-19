# @TEST-DOC: MP-BGP L3VPN: 2 ICMP frames behind a two-label stack
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MP_BGP_MPLS_CAPTURE_ping.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
