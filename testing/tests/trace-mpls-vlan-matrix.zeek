# @TEST-DOC: VLAN tags on either side of an MPLS pseudowire: provider 802.1Q, provider QinQ, untagged provider, customer 802.1Q and QinQ inside a control-word pseudowire, plus IP over MPLS on a tagged link. mpls_header.log should carry only provider tags; conn.log keeps the first and last tag Zeek sees (triple_tagged_vlan_unsupported when a third overwrites inner_vlan).
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/mpls_vlan_matrix.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
