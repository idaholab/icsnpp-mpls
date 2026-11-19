# @TEST-DOC: 11 labeled LDP frames (TCP and UDP 646) over IP
# @TEST-EXEC: bash $SCRIPTS/run-mpls-trace $TRACES/LDP_Ethernet_FrameRelay.pcap
# @TEST-EXEC: btest-diff mpls.out
# @TEST-EXEC: btest-diff conn.out
# @TEST-EXEC: btest-diff weird.out
