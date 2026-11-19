# @TEST-DOC: EoMPLS with 802.1Q: 10 pseudowire frames with a control word carrying VLAN-tagged ICMP
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/EoMPLS_802.1q.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
