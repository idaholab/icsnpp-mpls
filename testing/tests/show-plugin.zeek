# @TEST-EXEC: zeek -NN ICSNPP::MPLS | sed -e 's/version.*)/version)/g' -e '/^$/d' >output
# @TEST-EXEC: btest-diff output
