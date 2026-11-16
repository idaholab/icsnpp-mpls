# @TEST-DOC: Verify MPLS label-stack logging with the included capture
# @TEST-EXEC: zeek -C -r $TRACES/mpls.pcap >zeek-output 2>zeek-error
# @TEST-EXEC: test ! -s zeek-output
# @TEST-EXEC: test ! -s zeek-error
# @TEST-EXEC: zeek-cut labels experimentals bottom_of_stack time_to_live < mpls_header.log >output
# @TEST-EXEC: btest-diff output
