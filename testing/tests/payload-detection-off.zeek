# @TEST-DOC: With detection off, everything goes to the default analyzer and payload stays unset
# @TEST-EXEC: zeek -C -r $TRACES/mpls-payload-detection.pcap MPLSLogger::detect_payload=F MPLSLogger::log_every_packet=T >zeek-output 2>zeek-error
# @TEST-EXEC: test ! -s zeek-error
# @TEST-EXEC: zeek-cut payload labels < mpls_header.log >output
# @TEST-EXEC: btest-diff output
