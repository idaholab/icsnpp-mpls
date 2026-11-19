# @TEST-DOC: 15 frames with a two-label stack carrying ICMP and Telnet
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MPLS_Two_Level.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
