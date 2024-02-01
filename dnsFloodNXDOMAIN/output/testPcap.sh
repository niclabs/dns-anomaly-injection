#!/bin/bash


COMMAND1="mergecap $1 -w - |dnsanalyzer -w 600  -i 600 -a 8 -p "both" -t 1.2 -P "srcIP" -c 25 -s 32 -g "./" -q  > $2"
echo "${COMMAND1}"
sh -c "${COMMAND1}"
COMMAND2="gnuplot "*.gp""
echo "${COMMAND2}"
sh -c "${COMMAND2}"