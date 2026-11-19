# @TEST-DOC: Synthetic: label 299776 inside VLAN 100
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/mpls_large_label_vlan.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
