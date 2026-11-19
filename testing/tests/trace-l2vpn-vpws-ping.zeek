# @TEST-DOC: VPWS: 2 pseudowire frames with a control word carrying VLAN-tagged ICMP
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/L2VPN_VPWS_ping.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
