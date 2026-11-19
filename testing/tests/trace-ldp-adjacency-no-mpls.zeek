# @TEST-DOC: LDP control plane with no labeled frames: no mpls_header.log
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/LDP_Adjacency_no_MPLS.pcap
# @TEST-EXEC: test ! -f mpls_header.log
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
