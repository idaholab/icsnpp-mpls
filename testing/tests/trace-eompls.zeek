# @TEST-DOC: EoMPLS: 30 Ethernet pseudowire frames with a control word (STP, CDP, ARP, ICMP) and 20 LDP frames over IP
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/EoMPLS.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
