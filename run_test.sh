#!/bin/bash

./rew-sploit.py --test tests/run_rc4.trn
./rew-sploit.py --test tests/run_rc4_pcap.trn
./rew-sploit.py --test tests/run_shikata.trn
./rew-sploit.py --test tests/run_rc4_64.trn
./rew-sploit.py --test tests/run_meterpreter_reverse_tcp.trn
./rew-sploit.py --test tests/run_chacha.trn

##
## Run non-standard tests
##

# Set colors 
GREEN='\033[0;32m'
RED='\033[0;31m'
CLEAR='\033[0m'

# 1: o-llvm
echo
echo "============== o-llvm test =============="
SECONDS=0
./rew-sploit.py "emulate_payload -P samples/o-llvm.exe > /tmp/o-llvm.tst" "quit" > /dev/null 2>&1

echo "Ran 1 test in ${SECONDS}s"
echo

diff /tmp/o-llvm.tst ./tests/run_o-llvm.trn 2>/dev/null
if [ $? -eq 0 ]
then
	echo OK
	printf "${GREEN}============== o-llvm passed ==============${CLEAR}"
else
	echo KO
	printf "${RED}============== o-llvm failed ==============${CLEAR}"
fi
rm -f /tmp/o-llvm.tst

# 2: antidebug
echo
echo "============== antidebug test =============="
SECONDS=0
./rew-sploit.py "emulate_antidebug -P samples/antidebug64.exe > /tmp/antidebug.tst" "quit" > /dev/null 2>&1

echo "Ran 1 test in ${SECONDS}s"
echo

diff /tmp/antidebug.tst ./tests/run_antidebug.trn 2>/dev/null
if [ $? -eq 0 ]
then
	echo OK
	printf "${GREEN}============== antidebug passed ==============${CLEAR}"
else
	echo KO
	printf "${RED}============== antidebug failed ==============${CLEAR}"
fi
rm -f /tmp/antidebug.tst
