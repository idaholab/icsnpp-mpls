# @TEST-DOC: 2 LSP traceroute frames with label TTLs 1 and 2
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MPLS_trace.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
