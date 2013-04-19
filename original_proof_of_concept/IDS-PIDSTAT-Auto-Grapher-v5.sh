#!/bin/bash
#
# 1.) set the global's for output file and input pcap
# 2.) also set the human readable process name and test ID
# 3.) while your at it, set the path to the directory containing your pcaps
#
# Script Assumes:
# 1.) You are running as root - else exit
# 2.) You do not have the log directories or anything in them allready - else exit
# 3.) You have snort and suricata installed and configured allready
#
# It should be noted that since we're only measureing the process ID specified in pidstat
# we don't need to worry about results being skewed by running this script.
#
# Version: v4
#
# Revision Control:
# 	Version 1: Supported Creating a PidStat Log From Suricata
#	Version 2: Supported Creating a PidStat Log and CSV From Suricata
#	Version 3: Supported Creating a PidStat Log and CSV as well as a Packets Per Minute Log all for Suricata
#	Version 4: Same as V.3 but also added suport for creating a PidStat Log and CSV for Snort (no snort pps csv yet)
#	Version 5: Same as V.3 but now with snort PPS processing and output to CSV
#	Version 6: (PLAN: GNU-PLOT)
#
# whitejs@clarkson.edu

### Variables ###
LOG_OUTPUT_DIR="/root/IDS-Test-Logs/"
CSV_OUTPUT_DIR="/root/IDS-Test-CSVs/"
NUM_CORES_THIS_ROUND=24 	#This is just for logfile nameing purposes
LOG_INTERVAL=1			#Chose 8 seconds as default because it matches up with Suricata Log
LOG_DURATION=1000
PROCESS_ID_1="suricata"
PROCESS_ID_2="snort"
TEST_ID="1"
PCAP_DIR="/root/pytbull-pcaps/"
PCAP_NAMES="*.pcap"
IDS_CONFIG_FILE="/etc/suricata/suricata.yaml"
IDS_CONFIG_FILE_2="/etc/snort/snort.cfg"

### Make Sure We're Running As Root ###
if [[ $EUID -ne 0 ]]; then

  echo "This script will only work if you are root"
  exit 1

else

  clear

  ### Test If Directories Exist Before Creating Them ###
  if [ -d $LOG_OUTPUT_DIR ];then
    
    echo "Dirctories Exist, before continuing please move the data and rm the directories before we overwrite it."
    exit 1

  else

    ### Move Into the PCAP Directory Before Running ###
    cd $PCAP_DIR

    ### Walk through each of the pcap files and do the following ###
    for f in $PCAP_NAMES

    do
  
      ### clean up the snort and suricata stats files ###
      echo " " > /var/log/suricata/stats.logfile
      echo " " > /var/log/snort/snort.stats

      ### Setup the final Log and CSV Names ###
      LOG_NAME=$PROCESS_ID_1"_MEM-CPU_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".log"
      LOG_NAME_FINAL_CSV=$PROCESS_ID_1"_MEM-CPU_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".csv"
      LOG_NAME_PPS_CSV=$PROCESS_ID_1"_PPS_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".csv"
      LOG_NAME_2=$PROCESS_ID_2"_MEM-CPU_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".log"
      LOG_NAME_FINAL_CSV_2=$PROCESS_ID_2"_MEM-CPU_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".csv"
      LOG_NAME_PPS_CSV_2=$PROCESS_ID_2"_PPS_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".csv"

      ### Print User Messages ###
      echo -e "A Log file named \033[1m$LOG_NAME\033[0m will be generated"
      echo -e "The Final CSV file named \033[1m$LOG_NAME_FINAL_CSV\033[0m will also be generated"

      ### Create The Log Directory and Files ###
      mkdir -p $LOG_OUTPUT_DIR
      mkdir -p $CSV_OUTPUT_DIR
      touch $LOG_NAME
      touch $LOG_NAME_FINAL_CSV

      ### Clear Up Suricata Stats Log File ###
      echo " " > /var/log/suricata/stats.log

      ### Run PIDSTAT and Generate Log File for Suricata###
      pidstat $LOG_INTERVAL $LOG_DURATION -C $PROCESS_ID_1 -r -u -h > $LOG_NAME &

      ### Run Suricata Against Defined PCap ###
      suricata -c $IDS_CONFIG_FILE -r $f

      ### Setup Final CSV Log File for Suricata ###
      echo "Time,PID,%usr,%system,%guest,%CPU,CPU,minflt/s,majflt/s,VSZ (KB),RSS (KB),%MEM,Command" > $LOG_NAME_FINAL_CSV

      ### Convert PIDSTAT Log File For Suricata To CSV ###
      sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $LOG_NAME >> $LOG_NAME_FINAL_CSV

      ### This is really dirty, you probably should never do this. ###
      ### This takes two items of interest (time and ipv4 decode (and a third calculated pps)###
      ### "otherwise known as packet count) and puts them together into a csv file ###

      cat /var/log/suricata/stats.log | grep "Date" | cut -c 21-28 > temp1.file
      cat /var/log/suricata/stats.log | grep "decoder.ipv4" | cut -c 57-100 > temp2.file

      N=1
      total=$(sed -n '$=' temp2.file)

      until [ "$N" -eq $total ]
	do
	  S1=$N
	  ((S2=N+1))
	  N=$S2
	  VAL1=$(sed -n "$S1 p" temp2.file)
	  VAL2=$(sed -n "$S2 p" temp2.file)
	  echo $((VAL2 - VAL1)) >> temp3.file
	done

      echo "time,packet count,pps" > $LOG_NAME_PPS_CSV
      paste temp1.file temp2.file temp3.file | sed 's/\t/,/g' >> $LOG_NAME_PPS_CSV

      ### Stop PIDSTAT so that it doesn't blow up on next loop ###
      killall pidstat

      ### Clean up temp files ###
      rm temp1.file
      rm temp2.file
      rm temp3.file

      ### Move Everything to proper locations ###
      mv $LOG_NAME $LOG_OUTPUT_DIR
      mv $LOG_NAME_FINAL_CSV $CSV_OUTPUT_DIR
      mv $LOG_NAME_PPS_CSV $CSV_OUTPUT_DIR

      ### AND NOW FOR THE SNORT PORTION OF OUR PROGRAM ###

      ### Run PIDSTAT and Generate Log File for Snort###
      pidstat $LOG_INTERVAL $LOG_DURATION -C $PROCESS_ID_2 -r -u -h > $LOG_NAME_2 &

      ### Run Snort Against Defined PCap ###
      snort -c $IDS_CONFIG_FILE_2 -r $f

      ### Setup Final CSV Log File For Snort###
      echo "Time,PID,%usr,%system,%guest,%CPU,CPU,minflt/s,majflt/s,VSZ (KB),RSS (KB),%MEM,Command" > $LOG_NAME_FINAL_CSV_2

      ### Convert PIDSTAT Log File For Snort To CSV ###
      sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $LOG_NAME >> $LOG_NAME_FINAL_CSV_2

      ### Again this will be another very dirty section to get the packets per second ###
      ### Statistics from snort. Specifically we're going to just take column 5 out ###
      ### the /var/log/snort/snort.stats file ###

      ### This first line sets up the column headers packet per (8) second csv for snort ### 
      echo "time, kilo-pps, pps" > $LOG_NAME_PPS_CSV_2

      ### This second single line is worth explaining a little more in detail ###
      ### The cut command (pipe 1) extracts column 1 and 5 from the snort.stats file
      ### The sed command (pipe 2) looks at pipe1 output and removes any lines with # or spaces ###
      ### The awk command (pipe 3) takes pipe2 output devides it up in columns by (,) and then creats a 3rd column which is a multiple of 1000 x column 2 ###
      cut -d, -f 1,5 /var/log/snort/snort.stats | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | awk 'BEGIN {FS=OFS=","}{$3=$2*1000}1' >> $LOG_NAME_PPS_CSV_2

      ### "A Place for Everything and Everything in its Place ###
      mv $LOG_NAME_2 $LOG_OUTPUT_DIR
      mv $LOG_NAME_FINAL_CSV_2 $CSV_OUTPUT_DIR
      mv $LOG_NAME_PPS_CSV_2 $CSV_OUTPUT_DIR

      ### Stop PIDSTAT so that it doesn't blow up on next loop ###
      killall pidstat

    done

  fi

fi

### Move Back Out of the PCAP Directory Before Exiting ###
cd ..
