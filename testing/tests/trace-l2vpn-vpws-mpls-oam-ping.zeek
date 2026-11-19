# @TEST-DOC: VPWS VCCV: 5 LSP ping requests behind a PW-ACH header with channel type 0x0021
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/L2VPN_VPWS_mpls_oam_ping.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
