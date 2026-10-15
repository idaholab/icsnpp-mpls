# @TEST-EXEC: zeek -NN Zeek::MPLSLogging | sed -e 's/version.*)/version)/g' -e '/^$/d' >output
# @TEST-EXEC: btest-diff output
