# @TEST-DOC: Verify MPLS label-stack logging with the included capture
# @TEST-EXEC: zeek -C -r $REPO/mpls.pcap $PACKAGE >zeek-output
# @TEST-EXEC: zeek-cut labels experimentals bottom_of_stack time_to_live < mpls_header.log >output
# @TEST-EXEC: btest-diff output
