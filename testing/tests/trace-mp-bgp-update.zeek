# @TEST-DOC: MP-BGP: 1 labeled BGP UPDATE
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MP_BGP_MPLS_CAPTURE_update.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
