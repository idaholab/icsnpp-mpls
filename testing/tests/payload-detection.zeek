# @TEST-DOC: Payload detection after the label stack: control word, no control word (GOOSE), PW-ACH IPv4 and non-IP, plain IPv4, explicit NULL
# @TEST-EXEC: zeek -C -r $TRACES/mpls-payload-detection.pcap policy/protocols/conn/mac-logging MPLSLogger::log_every_packet=T >zeek-output 2>zeek-error
# @TEST-EXEC: test ! -s zeek-error
# @TEST-EXEC: zeek-cut payload labels src_l2_addr dst_l2_addr uid < mpls_header.log | awk -F'\t' -v OFS='\t' '{ $5 = ($5 == "-" ? "no-uid" : "uid"); print }' >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut id.orig_h id.resp_h proto orig_l2_addr resp_l2_addr < conn.log | sort >conn-output
# @TEST-EXEC: btest-diff conn-output
