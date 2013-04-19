#! /bin/bash
#
# 1.) set the global's for output file and input pcap
# 2.) also set the human readable process name and test ID
# 3.) while your at it, set the path to the directory containing your pcaps
#
# whitejs@clarkson.edu

### Variables ###
LOG_OUTPUT_DIR="/root/IDS-Test-Logs/"
CSV_OUTPUT_DIR="/root/IDS-Test-CSVs/"
NUM_CORES_THIS_ROUND=24 	#This is just for logfile nameing purposes
LOG_INTERVAL=1
LOG_DURATION=1000
PROCESS_ID="suricata"
TEST_ID="1"
PCAP_NAMES="/root/pytbull-pcaps/*.pcap"
IDS_CONFIG_FILE="/etc/suricata/suricata.yaml"

### Make Sure We're Running As Root ###
if [[ $EUID -ne 0 ]]; then

  echo "This script will only work if you are root"
  exit 1

else

  ### Test If Directories Exist Before Creating Them ###
  if [ -d $LOG_OUTPUT_DIR ];then
    
    echo "Dirctories Exist, before continuing please move the data and rm the directories before we overwrite it."
    exit 1

  else

    ### Walk through each of the pcap files and do the following ###
    for f in $PCAP_NAMES

    do

      ### Setup the final Log and CSV Names ###
      LOG_NAME=$PROCESS_ID"_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".log"
      LOG_NAME_FINAL_CSV=$PROCESS_ID"_Test_"$TEST_ID"_Cores_"$NUM_CORES_THIS_ROUND"_PCap_"$f".csv"

      ### Print User Messages ###
      echo -e "A Log file named \033[1m$LOG_NAME\033[0m will be generated"
      echo -e "The Final CSV file named \033[1m$LOG_NAME_FINAL_CSV\033[0m will also be generated"

      ### Create The Log Directory and Files ###
      mkdir -p $LOG_OUTPUT_DIR
      mkdir -p $CSV_OUTPUT_DIR
      touch $LOG_NAME
      touch $LOG_NAME_FINAL_CSV

      ### Run PIDSTAT and Generate Log File ###
      pidstat $LOG_INTERVAL $LOG_DURATION -C $PROCESS_ID -r -u -h > $LOG_NAME &

      ### Run Suricata Against Defined PCap ###
      suricata -c $IDS_CONFIG_FILE -r $f

      ### Setup Final CSV Log File ###
      echo "Time, PID, %usr, %system, %guest, %CPU, CPU, KB_rd/s, KB_wr/s, KB_ccwr/s, Command" > $LOG_NAME_FINAL_CSV

      ### Convert PIDSTAT Log File To CSV ###
      sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $LOG_NAME >> $LOG_NAME_FINAL_CSV

      mv $LOG_NAME $LOG_OUTPUT_DIR
      mv $LOG_NAME_FINAL_CSV $CSV_OUTPUT_DIR

      killall pidstat

    done

  fi

fi
