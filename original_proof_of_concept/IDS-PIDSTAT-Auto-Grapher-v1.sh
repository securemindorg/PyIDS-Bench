#!/bin/bash
#
# set the global's for output file and input pcap
# also set the human readable process name and test ID
#
# whitejs@clarkson.edu
 

LOG_INTERVAL=1
LOG_DURATION=1000
PROCESS_ID="suricata"
TEST_ID="1"
PCAP_NAME="ctf08_1228495450_eth1.dump"
LOG_NAME=$PROCESS_ID"_Test_"$TEST_ID".log"
LOG_NAME_FINAL_CSV=$PROCESS_ID"_Test_"$TEST_ID".csv"
IDS_CONFIG_FILE="/etc/suricata/suricata.yaml"

echo -e "A Log file named \033[1m$LOG_NAME\033[0m will be generated"
echo -e "The Final CSV file named \033[1m$LOG_NAME_FINAL_CSV\033[0m will also be generated"

touch $LOG_NAME
touch $LOG_NAME_FINAL_CSV

pidstat $LOG_INTERVAL $LOG_DURATION -C $PROCESS_ID -r -u -h > $LOG_NAME & 
suricata -c $IDS_CONFIG_FILE -r $PCAP_NAME
echo "Time, PID, %usr, %system, %guest, %CPU, CPU, KB_rd/s, KB_wr/s, KB_ccwr/s, Command" > $LOG_NAME_FINAL_CSV
sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $LOG_NAME >> $LOG_NAME_FINAL_CSV

