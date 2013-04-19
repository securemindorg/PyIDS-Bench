#!/bin/bash
#
# ((THIS ENTIRE THING SHOULD BE RE-WRITTEN IN ANOTHER LANGUAGE))
# 
#
# (A side note, you'll notice that in various locations thoughout this script I use "touch" 
# to create a file before it's used, not always but sometimes. These are generally for a 
# reason; many of the shell utilities being called will not directly output to a non existant
# file with ">" this is generally do to how they handle standard i/o. So if you make 
# modifications to this script please do not take them out, you'll end up with errors)
#
# Script Assumes:
# 1.) You are running as root - else exit
# 2.) You do not have the log directories or anything in them allready - else exit
# 3.) You have snort and suricata installed and configured allready
# 4.) You are using the defined Directory Structure
# 5.) You have all the config files listed and in the correct place
# 6.) You have all the rule packs listed and in the right place
#
# It should be noted that since we're only measureing the process ID specified in pidstat
# we don't need to worry about results being skewed by running this script.
#
# Version: v9
#
# Revision Control:
# 	Version 1: Supported Creating a PidStat Log From Suricata
#	Version 2: Supported Creating a PidStat Log and CSV From Suricata
#	Version 3: Supported Creating a PidStat Log and CSV as well as a Packets Per Minute Log all for Suricata
#	Version 4: Same as V.3 but also added suport for creating a PidStat Log and CSV for Snort (no snort pps csv yet)
#	Version 5: Same as V.3 but now with snort PPS processing and output to CSV
#	Version 6: Same as V.5 but I've added calculation of max min average for PPS (both snort and suricata, I'm pushing GNU-PLOT off to next version
#	Version 7: This was a big revision, I stabalized pidstat command to get true 1 second intervals, 
#                                           added time conversion for everything, 
#                                           fixed a bunch of bugs,
#                                           added a usefull summary logfile
#	Version 8: This version adds: 	Turned tests into one massive ugly function
#					Calls that function twice, once for testing with Emerging Threats Rules and Once Without
#					Output is not in two directories, one for rule based tests and one without
#					Still need to replace pidstat with ps, need to update process log script and add to this, need to add options menu (tests, or process logs) 
#	Version 9: This version adds:	Started adding support for running for additional PCAP Files based on individual Pytbull Captures (not finished)
#					Additional Runs for other Suricata / Snort Config Files (No-Rules/ET_Free-Rules/ET_Pro-Rules/VRT_Free-Rules) as well as (Optomized Suricata for Multi Core)
#					Adds command line options section
#					Adds option for running same tests multiple times and getting the standard deviation.
# 					Variables Are Now Defined for output files instead of hard-coded
#					Added Final Log Parsing Capability as a function that can be called with command line option
#					Added ~250 Lines, Removed ~100 Lines, Turned all instances of Min/Max/Mean into single function
#					Still should have average/min/max calculations turned into a seperate function but they work as is (just extra junk code)
#	Version 10: This version adds:	-r option for shorter but more comprehensive no-rules tests.
#
#
# whitejs@clarkson.edu

### Left in for error handeling ###
#echo "starting"
#set -v on
#set -x on


#################
### Settings  ###
#################

     # Define your pcap file location here:
     PCAP_FILE="ictf2010.pcap"
     PCAP_FILE_PytBull_1="/mnt/pcaps/pytbull/pytbull-pcap-test-1.pcap"
     PCAP_FILE_PytBull_2="/mnt/pcaps/pytbull/pytbull-pcap-test-2.pcap"
     PCAP_FILE_PytBull_3="/mnt/pcaps/pytbull/pytbull-pcap-test-3.pcap"
     PCAP_FILE_PytBull_4="/mnt/pcaps/pytbull/pytbull-pcap-test-4.pcap"
     PCAP_FILE_PytBull_5="/mnt/pcaps/pytbull/pytbull-pcap-test-5.pcap"
     PCAP_FILE_PytBull_6="/mnt/pcaps/pytbull/pytbull-pcap-test-6.pcap"
     PCAP_FILE_PytBull_ALL="/mnt/pcaps/pytbull/pytbull-pcap-test-ALL.pcap"

     # Define your suricata configs here:
     SURICATA_CONFIG="default"
     SURICATA_CONFIG_NO_RULES="/etc/suricata/suricata.yaml_no_rules"
     SURICATA_CONFIG_NO_RULES_TWEEKED_FOR_MULTI_CORE="/etc/suricata/suricata.yaml_no_rules_suricata_multi_core_tweeked"
     SURICATA_CONFIG_ET_FREE_RULES="/etc/suricata/suricata.yaml_et_free"
     SURICATA_CONFIG_ET_PRO_RULES="/etc/suricata/suricata.yaml_et_pro"
     SURICATA_CONFIG_VRT_FREE_RULES="/etc/suricata/suricata.yaml_vrt"

     # Define your snort configs here:
     SNORT_CONFIG="default"
     SNORT_CONFIG_NO_RULES="/etc/snort/snort.conf_no_rules"
     SNORT_CONFIG_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE="/etc/snort/snort.conf_no_rules_suricata_multi_core_tweeked"
     SNORT_CONFIG_ET_FREE_RULES="/etc/snort/snort.conf_et_free"
     SNORT_CONFIG_ET_PRO_RULES="/etc/snort/snort.conf_et_pro"
     SNORT_CONFIG_VRT_FREE_RULES="/etc/snort/snort.conf_vrt"

     # Define your random settings here:
     SAMPLING_TIME=120 #in seconds
     MAX_LOG_DURATION=4000 #in seconds
     LOG_INTERVAL=1 #in seconds
     OUTPUT_DIRECTORY="tests_output"
     IDS_COMPARISON_TESTING_LOG="run.log"
     VERSION="Version 10"

     # Define your output files directory here:
     SURICATA_PROCESS_STATS_CSV="default"
     SURICATA_PROCESS_STATS_CSV_NO_RULES="process-suricata-stats_no_rules.csv"
     SURICATA_PROCESS_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE="process-suricata-stats_no_rules_suricta_multi_core_tweeked.csv"
     SURICATA_PROCESS_STATS_CSV_ET_FREE_RULES="process-suricata-stats_et_free_rules.csv"
     SURICATA_PROCESS_STATS_CSV_ET_PRO_RULES="process-suricata-stats_et_pro_rules.csv"
     SURICATA_PROCESS_STATS_CSV_VRT_FREE_RULES="process-suricata-stats_vrt_rules.csv"

     SURICATA_STATS_CSV="default"
     SURICATA_STATS_CSV_NO_RULES="suricata-stats_no_rules.csv"
     SURICATA_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE="suricata-stats_no_rules_suricata_multi_core_tweeked.csv"
     SURICATA_STATS_CSV_ET_FREE_RULES="suricata-stats_et_free_rules.csv"
     SURICATA_STATS_CSV_ET_PRO_RULES="suricata-stats_et_pro_rules.csv"
     SURICATA_STATS_CSV_VRT_FREE_RULES="suricata-stats_vrt_rules.csv"

     SNORT_PROCESS_STATS_CSV="default"
     SNORT_PROCESS_STATS_CSV_NO_RULES="process-snort-stats_no_rules.csv"
     SNORT_PROCESS_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE="process-snort-stats_no_rules_suricata_multi_core_tweeked.csv"
     SNORT_PROCESS_STATS_CSV_ET_FREE_RULES="process-snort-stats_et_free_rules.csv"
     SNORT_PROCESS_STATS_CSV_ET_PRO_RULES="process-snort-stats_et_pro_rules.csv"
     SNORT_PROCESS_STATS_CSV_VRT_FREE_RULES="process-snort-stats_vrt_rules.csv"

     SNORT_STATS_CSV="default"
     SNORT_STATS_CSV_NO_RULES="snort-stats_no_rules.csv" 
     SNORT_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE="snort-stats_no_rules_suricata_multi_core_tweeked.csv"
     SNORT_STATS_CSV_ET_FREE_RULES="snort-stats_et_free_rules.csv"
     SNORT_STATS_CSV_ET_PRO_RULES="snort-stats_et_pro_rules.csv"
     SNORT_STATS_CSV_VRT_FREE_RULES="snort-stats_vrt_rules.csv"

     # Define Log files and directories for log processing
     C1_CORE_LOG_DIR="1cpu-48g-t1/test_output/"
     C2_CORE_LOG_DIR="2cpu-48g-t1/test_output/"
     C3_CORE_LOG_DIR="3cpu-48g-t1/test_output/"
     C4_CORE_LOG_DIR="4cpu-48g-t1/test_output/"
     C5_CORE_LOG_DIR="5cpu-48g-t1/test_output/"
     C6_CORE_LOG_DIR="6cpu-48g-t1/test_output/"
     C8_CORE_LOG_DIR="8cpu-48g-t1/test_output/"
     C12_CORE_LOG_DIR="12cpu-48g-t1/test_output/"
     C18_CORE_LOG_DIR="18cpu-48g-t1/test_output/"
     C24_CORE_LOG_DIR="24cpu-48g-t1/test_output/"

     LOG_NAME="run.log"
     STD_LOG_NAME="std_run_log"
     MASTER_SUMMARY_LOG="master_summary.log"


#####################################################
### Make sure all other local variables are clear ###
#####################################################

     SURICATA_CPU_NUM_STATS=0
     SURICATA_CPU_PERCENT_STATS=0
     SURICATA_PROC_END_TIME=0
     SURICATA_PROC_START_TIME=0
     SURICATA_STATS_END_TIME=0
     SURICATA_STATS_START_TIME=0
     SURICATA_TOT_PROC_RUN_TIME=0
     SURICATA_TOT_STATS_RUN_TIME=0
     SURICATA_RSS_STATS=0
     SURICATA_MEM_PERCENT_STATS=0
     SURICATA_PPS_STATS=0

     SNORT_CPU_NUM_STATS=0
     SNORT_CPU_PERCENT_STATS=0
     SNORT_PROC_END_TIME=0
     SNORT_PROC_START_TIME=0
     SNORT_STATS_END_TIME=0
     SNORT_STATS_START_TIME=0
     SNORT_TOT_PROC_RUN_TIME=0
     SNORT_TOT_STATS_RUN_TIME=0
     SNORT_RSS_STATS=0
     SNORT_MEM_PERCENT_STATS=0
     SNORT_PPS_STATS=0

########################################
########################################
########### Define Functions ###########
########################################
########################################

##################################################
########### Command Line Options Usage ###########
##################################################

SCRIPT_USAGE ()
{
echo    "
	By:
	    Clarkson University
	    CS644 Advanced Topics in Operating Systems
	    Prof: Jeanna Matthews

		  Joshua White
		  Thomas Fitzsimmons
		  James Licata
	      

        usage: $0 options

	Do not specify more then one command line option at a time, this script isnt setup to handle that yet.

        This script can run the tests or process the final results of multiple tests.

        OPTIONS:
           -h / -? Show this message
           -t      Runs the tests with the preconfigured pcaps
	   -d	   Runs all tests (like -t) but 5 times and calculates Std Deviations In Final Log CSV
           -p      Process the logs to create a single master log
           -s      Specifiy a PCap file like (-s test.pcap) 
		   This is usually used with -t
	   -v	   Prints Version Information
	   -r      Runs 5 instances of Snort / Suricata Tests without rules and calculates output with standard deviation

	Example Usage:

	  Run tests using specified PCap:
	    $0 -s test.pcap 

	  Run all tests using 7 predefined pcaps:
	    $0 -t
        "
}

####################################################
########### Define Min Max Mean Function ###########
####################################################

function MIN_MAX_MEAN {

awk 'BEGIN {FS=","}
                  min=="" {
                  min=max=$1 ;
                  total+=$1;
                  }
                  {
                    if ($1 > max) {max = $1;};
                    if ($1 < min) {min = $1;};
                    total += $1
                    count += 1
                  }
                  END {
                    print min",",max",",total/count;
                  }'

}

#########################################################
########### RUN TESTS - Big and Ugly Function ###########
#########################################################

RUNTESTS ()
{

# this incriments the output directory name

STD_N=0
STD_LOOPS=5

until [ "$STD_N" -eq $STD_LOOPS ]
  do
  STD_S1=$STD_N
  ((STD_S2=STD_N+1))
  STD_N=$STD_S2
  OUTPUT_DIRECTORY=$STD_N

     # Clean Everything
     echo " " > /var/log/suricata/stats.log && echo " " > /var/log/snort/snort.stats

     # make the output directory
     mkdir $OUTPUT_DIRECTORY

     ####################################
     ### Startup Pidstat and Suricata ###
     ####################################

	# I'm going back to doing this the pidstat way because with some tweaking it's a better way 
	pidstat $LOG_INTERVAL $MAX_LOG_DURATION -C suricata -r -u -h > out.2 &

	# start suricata
	suricata -c $SURICATA_CONFIG -r $PCAP_FILE

	# Stop PIDSTAT so that it doesn't blow up on next loop 
	killall pidstat

     ####################################################
     ### Create the Final Suricata Process Stats file ###
     ####################################################

	# Setup Final CSV Log File for Suricata 
	echo "Time,PID,%usr,%system,%guest,%CPU,CPU,minflt/s,majflt/s,VSZ (KB),RSS (KB),%MEM,Command" > $SURICATA_PROCESS_STATS_CSV

	# Convert PIDSTAT Log File For Suricata To CSV 
	cat out.2 | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13 >> temp9.file

	# Convert Timestamp for PIDSTAT Log File For Suricata To CSV 
	cat out.2 | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1 > temp10.file 

	###################################################
	### Convert Time Stamp For Suricata Pidstat CSV ###
	###################################################

	      # Set the input variable for timestamp conversion
	      INPUT="temp10.file"

	      # This converts the unix timestamp to human readable and selects only the hh:mm:ss portion of it for printout 
	      while read line
		do
		  date -d @$line | cut -d" " -f 4 >> temp11.file
		done < "$INPUT" 

	      # Finally we put this all together 
	      paste temp11.file temp9.file | sed 's/\t/,/g' >> $SURICATA_PROCESS_STATS_CSV

	#########################################################
	### Start the grab and convert for Suricata stats.log ###
	#########################################################

	      # get and process suricata's own stats file
	      cat /var/log/suricata/stats.log | grep "Date" | cut -c 21-28 > temp1.file
	      cat /var/log/suricata/stats.log | grep "decoder.ipv4" | cut -c 57-100 >> temp2.file

	      paste temp1.file temp2.file | sed 's/\t/,/g' >> temp3.file

	      touch temp4.file
	      uniq temp3.file > temp4.file  

	      ######################################################
	      ### Calculate PPS based on Suricata's Packet Count ###
	      ######################################################

		    # This enters a 0 into the temp5.file, I do this to give the packet count first line something 
		    # to subtract since you can't subtract null
		    echo 0 > temp5.file
	
		    # Now we take the packet count column the suricata stats file and puts it into the newly 
		    # created temp5.file so we can calculate PPS
		    cat temp4.file | cut -d, -f 2 >> temp5.file 

		    # Subtract each line from the previous to calculate PPS
		    N=1
		    total=$(sed -n '$=' temp5.file)
	
		    touch temp4.file

		    until [ "$N" -eq $total ]
		      do
			S1=$N
			((S2=N+1))
			N=$S2
			VAL1=$(sed -n "$S1 p" temp5.file)
			VAL2=$(sed -n "$S2 p" temp5.file)
			echo $((VAL2 - VAL1)) >> temp6.file
		      done

	      #############################################################
	      ### Put it all together / Clean up / End Suricata Section ###     
	      #############################################################

		    echo "time,packet count,PPS" > $SURICATA_STATS_CSV
		    paste temp4.file temp6.file | sed 's/\t/,/g' >> $SURICATA_STATS_CSV

		    # clean up and get ready to start over with snort
		    rm -f out.* temp*.file

     #################################
     ### Startup PidStat and Snort ###
     #################################

	# I'm going back to doing this the pidstat way because with some tweaking it's a better way
	pidstat $LOG_INTERVAL $MAX_LOG_DURATION -C snort -r -u -h > out.2 &

	# start snort
	snort -c $SNORT_CONFIG -r $PCAP_FILE

	# Stop PIDSTAT so that it doesn't blow up on next loop 
	killall pidstat

     #################################################
     ### create the final snort process stats file ###
     #################################################

	### Setup Final CSV Log File for Snort ###
	echo "Time,PID,%usr,%system,%guest,%CPU,CPU,minflt/s,majflt/s,VSZ (KB),RSS (KB),%MEM,Command" > $SNORT_PROCESS_STATS_CSV

	### Convert PIDSTAT Log File For Snort To CSV ###
	cat out.2 | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13 >> temp9.file 

	### Convert Timestamp for PIDSTAT Log File For Snort To CSV ###
	cat out.2 | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1 > temp10.file

	################################################
	### Convert Time Stamp For Snort Pidstat CSV ###
	################################################

	      INPUT="temp10.file"

	      # this converts the unix timestamp to human readable and selects only the hh:mm:ss portion of it for printout
	      while read line
		do
		  date -d @$line | cut -d" " -f 4 >> temp11.file
		done < "$INPUT"  

	      # and finally we put this all together
	      paste temp11.file temp9.file | sed 's/\t/,/g' >> $SNORT_PROCESS_STATS_CSV

	########################################################
	### Start the grab and convert for Snort snort.stats ###
	########################################################

	      # get and process snort's own stats file
	      cut -d, -f 1 /var/log/snort/snort.stats | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' > temp1.file
	      cut -d, -f 5 /var/log/snort/snort.stats | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' > temp2.file

	      ################################################
	      ### Convert Time Stamp For Snort snort.stats ###
	      ################################################

		    INPUT="temp1.file"

		    # this converts the unix timestamp to human readable and selects only the hh:mm:ss portion of it for printout
		    while read line
		      do
			date -d @$line | cut -d" " -f 5 >> temp3.file
		      done < "$INPUT" # this sets up the final csv and gives it headers echo "time, kilo-pps, pps" > snort-stats.csv

	      ##########################################################
	      ### Put it all together / Clean up / End Snort Section ###
	      ##########################################################

		    # this setsup the snort-stats.csv file headers
		    echo "time,k-pps,pps" > $SNORT_STATS_CSV

		    # this line takes the timestamps and the packet count and calculates a third column PPS and puts them into the csv
		    paste temp3.file temp2.file | sed 's/\t/,/g' | uniq | awk 'BEGIN {FS=OFS=","}{$3=$2*1000}1' >> $SNORT_STATS_CSV

		    # clean up and get read to start over
		    rm -f out.* temp*.file

     ##########################
     ### Create the Run Log ###
     ##########################

           # Setup the logfile headers
           echo "IDS Name,PCAP Name,Total Process Time (Sec),Total Run Time (Sec),Min # CPU,Max # CPU,AVG # CPU, Min % CPU,Max % CPU,Avg % CPU,Min RSS (KB),Max RSS (KB),Avg RSS (KB), Min % Mem,Max % Mem,Avg % Mem,Min PPS,Max PPS,Avg PPS,Total Packets Report Processed" > $IDS_COMPARISON_TESTING_LOG

           ########################################################################
           ### Calculate the total process run time for both snort and suricata ###
           ########################################################################

                 # Get suricata start and stop process times
                 SURICATA_PROC_START_TIME=$(head -n 2 $SURICATA_PROCESS_STATS_CSV | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SURICATA_PROC_END_TIME=$(tail -n 1 $SURICATA_PROCESS_STATS_CSV | cut -d, -f 1)

                 # Get snort start and stop process times
                 SNORT_PROC_START_TIME=$(head -n 2 $SNORT_PROCESS_STATS_CSV | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SNORT_PROC_END_TIME=$(tail -n 1 $SNORT_PROCESS_STATS_CSV | cut -d, -f 1)

                 # Calculate Suricata total Process run time
                 let SURICATA_TOT_PROC_RUN_TIME=$(date +%s -d $SURICATA_PROC_END_TIME)-$(date +%s -d $SURICATA_PROC_START_TIME)

                 # Calculate Snort total Process run time
                 let SNORT_TOT_PROC_RUN_TIME=$(date +%s -d $SNORT_PROC_END_TIME)-$(date +%s -d $SNORT_PROC_START_TIME)

           #######################################################################
           ### Calculate the total actual run time for both snort and suricata ###
           #######################################################################

                 # Get suricata start and stop process times
                 SURICATA_STATS_START_TIME=$(head -n 2 $SURICATA_STATS_CSV | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SURICATA_STATS_END_TIME=$(tail -n 1 $SURICATA_STATS_CSV | cut -d, -f 1)

                 # Get snort start and stop process times
                 SNORT_STATS_START_TIME=$(head -n 2 $SNORT_STATS_CSV | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SNORT_STATS_END_TIME=$(tail -n 1 $SNORT_STATS_CSV | cut -d, -f 1)

                 # Calculate Suricata total Process run time
                 let SURICATA_TOT_STATS_RUN_TIME=$(date +%s -d $SURICATA_STATS_END_TIME)-$(date +%s -d $SURICATA_STATS_START_TIME)

                 # Calculate Snort total Process run time
                 let SNORT_TOT_STATS_RUN_TIME=$(date +%s -d $SNORT_STATS_END_TIME)-$(date +%s -d $SNORT_STATS_START_TIME)

           ################################################################################
           ### Calculate the CPU stats (MIN, MAX, AVG) Used for both snort and suricata ###
           ################################################################################

                SURICATA_CPU_NUM_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SURICATA_PROCESS_STATS_CSV | cut -d, -f 7 | MIN_MAX_MEAN)

                SNORT_CPU_NUM_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SNORT_PROCESS_STATS_CSV | cut -d, -f 7 | MIN_MAX_MEAN)

          ########################################################################################
          ### Calculate the CPU % Usage stats (MIN, MAX, AVG) Used for both snort and suricata ###
          ########################################################################################

                SURICATA_CPU_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SURICATA_PROCESS_STATS_CSV | cut -d, -f 6 | MIN_MAX_MEAN)

                SNORT_CPU_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SNORT_PROCESS_STATS_CSV | cut -d, -f 6 | MIN_MAX_MEAN)

          #####################################################################################################
          ### Calculate the RSS (MEMORY) Usage stats in KB (MIN, MAX, AVG) Used for both snort and suricata ###
          #####################################################################################################

                SURICATA_RSS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SURICATA_PROCESS_STATS_CSV | cut -d, -f 11 | MIN_MAX_MEAN)

                SNORT_RSS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SNORT_PROCESS_STATS_CSV | cut -d, -f 11 | MIN_MAX_MEAN)

          ########################################################################################
          ### Calculate the MEM % Usage stats (MIN, MAX, AVG) Used for both snort and suricata ###
          ########################################################################################

                SURICATA_MEM_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SURICATA_PROCESS_STATS_CSV | cut -d, -f 12 | MIN_MAX_MEAN)

                SNORT_MEM_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SNORT_PROCESS_STATS_CSV | cut -d, -f 12 | MIN_MAX_MEAN)

          ########################################################################
          ### Calculate PPS (MIN, MAX, AVG, TOTAL) for both snort and suricata ###
          ########################################################################

                SURICATA_PPS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SURICATA_STATS_CSV | cut -d, -f 3 | MIN_MAX_MEAN)

                SNORT_PPS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' $SNORT_STATS_CSV | cut -d, -f 3 | MIN_MAX_MEAN)

     # print the final entries into the log file
     echo "suricata,$PCAP_FILE,$SURICATA_TOT_PROC_RUN_TIME,$SURICATA_TOT_STATS_RUN_TIME,$SURICATA_CPU_NUM_STATS,$SURICATA_CPU_PERCENT_STATS,$SURICATA_RSS_STATS,$SURICATA_MEM_PERCENT_STATS,$SURICATA_PPS_STATS" | sed 's/ //g' >> $IDS_COMPARISON_TESTING_LOG
     echo "snort,$PCAP_FILE,$SNORT_TOT_PROC_RUN_TIME,$SNORT_TOT_STATS_RUN_TIME,$SNORT_CPU_NUM_STATS,$SNORT_CPU_PERCENT_STATS,$SNORT_RSS_STATS,$SNORT_MEM_PERCENT_STATS,$SNORT_PPS_STATS" | sed 's/ //g'>> $IDS_COMPARISON_TESTING_LOG

     ############################################
     ### Move Everything to it's proper place ###
     ############################################

     mv *.csv $OUTPUT_DIRECTORY
     mv $IDS_COMPARISON_TESTING_LOG $OUTPUT_DIRECTORY

     rm -rf temp*.file

  done
##############################################
### End the Run Test Big and Ugly function ###
##############################################
}


##############################################
########### Run All Tests Function ###########
##############################################

function RUN_ALL_TESTS {

  ############################################################
  ### Execute Second Round of Tests With No Rules Included ###
  ############################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_NO_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_NO_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_NO_RULES

  SNORT_CONFIG=$SNORT_CONFIG_NO_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_NO_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_NO_RULES

  # Runs Tests
  RUNTESTS

  ###################################################################################
  ### Execute Second Round of Tests With No Rules Included And Suricata Optomized ###
  ###################################################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_NO_RULES_TWEEKED_FOR_MULTI_CORE
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE

  SNORT_CONFIG=$SNORT_CONFIG_NO_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE
  SNORT_STATS_CSV=$SNORT_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE

  # Runs Tests
  RUNTESTS

  #################################################################
  ### Execute Second Round of Tests With ET Free Rules Included ###
  #################################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_ET_FREE_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_ET_FREE_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_ET_FREE_RULES

  SNORT_CONFIG=$SNORT_CONFIG_ET_FREE_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_ET_FREE_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_ET_FREE_RULES

  # Runs Tests
  RUNTESTS

  ################################################################
  ### Execute Second Round of Tests With ET Pro Rules Included ###
  ################################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_ET_PRO_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_ET_PRO_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_ET_PRO_RULES

  SNORT_CONFIG=$SNORT_CONFIG_ET_PRO_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_ET_PRO_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_ET_PRO_RULES

  # Runs Tests
  RUNTESTS

  ##################################################################
  ### Execute Second Round of Tests With VRT Free Rules Included ###
  ##################################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_VRT_FREE_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_VRT_FREE_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_VRT_FREE_RULES

  SNORT_CONFIG=$SNORT_CONFIG_VRT_FREE_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_VRT_FREE_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_VRT_FREE_RULES

  # Runs Tests
  RUNTESTS

  #################################
  ### Run the Pass Log Function ###
  #################################

  PROCESS_PASS_LOGS

##################################
### End Run All Tests Function ###
##################################

}
 
################################################
########### Calculate Std Deviation ############
################################################

function CALCULATE_TESTS_STD_DEVIATION {

awk '{ lines=FNR; arr[lines]=$1; sum+=$1}
     END{ avg=sum/lines
     sum=0;
     for(i=1; i<=lines; i++)
        { v=arr[i]-avg;
          sum+= v*v
        }
     printf("n=%d avg=%f  stddev=%f\n",
            lines, avg, sqrt( sum/( lines - 1) ) ) } ' $TEMP_FILE 

}

# This creates the master tests_run log file for this round of tests
function STD_DEV_PROCESSLOGFILES {

rm -rf temp*.file

#echo   "Snort - PCAP Name,\
#	Snort - Average All Runs Total Process Time (Sec),\
#	Snort - Average All Runs Total Run Time (Sec),\
#	Snort - Average All Runs Min # CPU,\
#	Snort - Average All Runs Max # CPU,\
#	Snort - Average All Runs AVG # CPU,\
#	Snort - Average All Runs Min % CPU,\
#	Snort - Average All Runs Max % CPU,\
#	Snort - Average All Runs Avg % CPU,\
#	Snort - Average All Runs Min RSS (KB),\
#	Snort - Average All Runs Max RSS (KB),\
#	Snort - Average All Runs Avg RSS (KB),\
#	Snort - Average All Runs Min % Mem,\
#	Snort - Average All Runs Max % Mem,\
#	Snort - Average All Runs Avg % Mem,\
#	Snort - Average All Runs Min PPS,\
#	Snort - Average All Runs Max PPS,\
#	Snort - Average All Runs Avg PPS
#	Suricata - PCAP Name,\
#	Suricata - Average All Runs Total Process Time (Sec),\
#	Suricata - Average All Runs Total Run Time (Sec),\
#	Suricata - Average All Runs Min # CPU,\
#	Suricata - Average All Runs Max # CPU,\
#	Suricata - Average All Runs AVG # CPU,\
#	Suricata - Average All Runs Min % CPU,\
#	Suricata - Average All Runs Max % CPU,\
#	Suricata - Average All Runs Avg % CPU,\
#	Suricata - Average All Runs Min RSS (KB),\
#	Suricata - Average All Runs Avg RSS (KB),\
#	Suricata - Average All Runs Min % Mem,\
#	Suricata - Average All Runs Avg % Mem,\
#	Suricata - Average All Runs Min PPS,\
#	Suricata - Average All Runs Max PPS,\
#	Suricata - Average All Runs Avg PPS" > $STD_LOG_NAME

cat 1/$LOG_NAME | grep snort | cut -d, -f 19 >> temp1.file
cat 2/$LOG_NAME | grep snort | cut -d, -f 19 >> temp1.file
cat 3/$LOG_NAME | grep snort | cut -d, -f 19 >> temp1.file
cat 4/$LOG_NAME | grep snort | cut -d, -f 19 >> temp1.file
cat 5/$LOG_NAME | grep snort | cut -d, -f 19 >> temp1.file

cat 1/$LOG_NAME | grep suricata | cut -d, -f 19 >> temp2.file
cat 2/$LOG_NAME | grep suricata | cut -d, -f 19 >> temp2.file
cat 3/$LOG_NAME | grep suricata | cut -d, -f 19 >> temp2.file
cat 4/$LOG_NAME | grep suricata | cut -d, -f 19 >> temp2.file
cat 5/$LOG_NAME | grep suricata | cut -d, -f 19 >> temp2.file

#N=1
#loops=7
#
#until [ "$N" -eq $loops ]
#  do
#    S1=$N
#    ((S2=N+1))
#    N=$S2
#    echo "," >> temp3.file
#  done


#This isn't right.... fix below , lables are wrong........

echo "Suricata - Standard Deviation All Runs PPS" >> temp4.file
TEMP_FILE=temp1.file
CALCULATE_TESTS_STD_DEVIATION >> temp4.file

echo "Snort - Standard Deviation All Runs PPS" >> temp5.file
TEMP_FILE=temp2.file
CALCULATE_TESTS_STD_DEVIATION >> temp5.file 

#paste temp1.file temp3.file temp2.file temp3.file temp5.file temp3.file temp4.file >> $STD_LOG_NAME
cat temp4.file >> $STD_LOG_NAME
cat temp5.file >> $STD_LOG_NAME

rm -rf temp*.file
### End of Function ###

}

#########################################################################
########### Process Log Files - Another Big and Ugly Function ###########
#########################################################################

function PROCESSLOGFILES {

echo   "Snort - PCAP Name,\
	Snort - Total Process Time (Sec),\
	Snort - Total Run Time (Sec),\
	Snort - Min # CPU,\
	Snort - Max # CPU,\
	Snort - AVG # CPU,\
	Snort - Min % CPU,\
	Snort - Max % CPU,\
	Snort - Avg % CPU,\
	Snort - Min RSS (KB),\
	Snort - Max RSS (KB),\
	Snort - Avg RSS (KB),\
	Snort - Min % Mem,\
	Snort - Max % Mem,\
	Snort - Avg % Mem,\
	Snort - Min PPS,\
	Snort - Max PPS,\
	Snort - Avg PPS,\
	Snort - Total Packets Report Processed," > temp1.file

echo   "Suricata - PCAP Name,\
	Suricata - Total Process Time (Sec),\
	Suricata - Total Run Time (Sec),\
	Suricata - Min # CPU,\
	Suricata - Max # CPU,\
	Suricata - AVG # CPU,\
	Suricata - Min % CPU,\
	Suricata - Max % CPU,\
	Suricata - Avg % CPU,\
	Suricata - Min RSS (KB),\
	Suricata - Max RSS (KB),\
	Suricata - Avg RSS (KB),\
	Suricata - Min % Mem,\
	Suricata - Max % Mem,\
	Suricata - Avg % Mem,\
	Suricata - Min PPS,\
	Suricata - Max PPS,\
	Suricata - Avg PPS,\
	Suricata - Total Packets Report Processed" > temp2.file

cat $C1_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C2_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C3_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C4_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C5_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C6_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C8_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C12_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C18_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file
cat $C24_CORE_LOG_DIR$LOG_NAME | grep snort | cut -d, -f 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp1.file

cat $C1_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C2_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C3_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C4_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C5_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C6_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C8_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C12_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C18_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file
cat $C24_CORE_LOG_DIR$LOG_NAME | grep suricata | cut -d, -f 3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 >> temp2.file

N=1
loops=11

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Core Test," >> temp4.file
echo "1," >> temp4.file 
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file
echo "6," >> temp4.file
echo "8," >> temp4.file
echo "12," >> temp4.file
echo "18," >> temp4.file
echo "24," >> temp4.file

paste temp4.file temp1.file temp3.file temp2.file >> $MASTER_SUMMARY_LOG

rm -f temp*.file

####################################
### END PROCESSLOGFILES FUNCTION ###
####################################

}


############################
############################
########### MAIN ###########
############################
############################


####################################################################
### Startup / Test For Root / Test For Existing Output Directory ###
####################################################################


    # make sure we're running as root
    if [[ $EUID -ne 0 ]]; then

      echo "This script will only work if you are root"
      exit 1

    else

      ################################
      ### Get Command Line Options ###
      ################################

    while getopts "htdpsvr" OPTION
    do
	case $OPTION in
	  h)
	      SCRIPT_USAGE
	      exit 1
	      ;;
	  t)
	      SNORT_CONFIG=$SNORT_CONFIG_NO_RULES
	      SURICATA_CONFIG=$SURICATA_CONFIG_NO_RULES
	      SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_NO_RULES
	      SURICATA_STATS_CSV=$SURICATA_STATS_CSV_NO_RULES
	      SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_NO_RULES 
	      SNORT_STATS_CSV=$SNORT_STATS_CSV_NO_RULES 
	      PCAP_FILE=$PCAP_FILE_PytBull_ALL
	      RUN_ALL_TESTS 
	      ;;
	  d)
	      SURICATA_CONFIG=$SURICATA_CONFIG_NO_RULES
	      SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_NO_RULES
	      SURICATA_STATS_CSV=$SURICATA_STATS_CSV_NO_RULES
	      SNORT_CONFIG=$SNORT_CONFIG_NO_RULES
	      SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_NO_RULES 
	      SNORT_STATS_CSV=$SNORT_STATS_CSV_NO_RULES 
	      RUN_ALL_TESTS
	      STD_DEV_PROCESSLOGFILES 
	      ;;
	  p)
	      PROCESSLOGFILES 
	      ;;
	  s)
	      PCAP_FILE=$OPTARG 
	      ;;
	  v)
	      echo $VERSION 
	      ;;
	  r)
	      SURICATA_CONFIG=$SURICATA_CONFIG_NO_RULES
	      SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_NO_RULES
	      SURICATA_STATS_CSV=$SURICATA_STATS_CSV_NO_RULES
	      SNORT_CONFIG=$SNORT_CONFIG_NO_RULES
	      SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_NO_RULES 
	      SNORT_STATS_CSV=$SNORT_STATS_CSV_NO_RULES 
	      RUNTESTS
	      STD_DEV_PROCESSLOGFILES 
	      ;;
	  ?)
	      SCRIPT_USAGE
	      exit 
	      ;;
	esac
    done

    fi


#set -v off
#set -x off
#echo "done"