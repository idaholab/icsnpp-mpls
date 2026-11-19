# @TEST-DOC: 11 frames, most with a non-zero Traffic Class
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MPLS_EXP.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
