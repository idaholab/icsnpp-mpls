# @TEST-DOC: VPLS: 4 pseudowire frames with a control word carrying ARP
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/L2VPN_VPLS_ARP.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
