#!/bin/bash
#bash inject_pcap.sh

INPUT="./input/"    #dns-hdns-02_2024-01-07_00_01.pcap.gz
OUTPUT="./output/test.pcap"
NUM_PACKET=10
INITIAL_TIME=0
DURATION=60
ZOMBIES=1
WINDOWS=0.01
PPS=42
SERVER="117.122.125.80"


for filename in $1; do
    #TMP="${OUTPUT}${filename:8:-3}"
    TMP=$OUTPUT
	  COMMAND="python3 DNSMain.py -i ${filename} -o ${TMP} -z 5 -n 5 -it 0 -p 10 -d 120 -d 300"
	  sh -c "${COMMAND}"
done

#
#if [ "x$1" = "x${REPLY}" ]; then
#	INPUT= $1
#	for filename in INPUT; do
#	  COMMAND= "python3 DNSMain.py -i ${filename} -o ${OUTPUT} -z 5 -n 5 -it 0 -p 10 -d 120 -d 300
#	  echo "#${COMMAND}"
#	  sh -c "${COMMAND}"
#
#else if [ "x$1" = "x${QUERY}" ]; then
#	POLICY="srcIP"
#	ADDITIONAL="-q"
#	COMMAND= " "
#	sh -c "${COMMAND}"
#else if [ "x$1" = "x${WHOLE}" ]; then
#	POLICY="srcIP"
#	COMMAND= " "
#	sh -c "${COMMAND}"
#else
#	echo "Usage: $0 ${REPLY}|${QUERY}|${WHOLE} \"pcap_file_wildcard\""
#fi
#fi
#fi