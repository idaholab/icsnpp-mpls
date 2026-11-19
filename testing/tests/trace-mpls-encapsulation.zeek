# @TEST-DOC: 5 single-label ICMP frames
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MPLS_Encapsulation.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
