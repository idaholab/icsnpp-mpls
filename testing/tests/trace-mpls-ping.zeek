# @TEST-DOC: 2 LSP ping frames, one behind an IPv4 explicit NULL label
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MPLS_ping.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
