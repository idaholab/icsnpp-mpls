# @TEST-DOC: 17 single-label frames carrying Telnet, ICMP, and RSVP
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/MPLS_Basic.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
