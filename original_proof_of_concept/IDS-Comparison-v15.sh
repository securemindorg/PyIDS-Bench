#!/bin/bash
#
# ((THIS ENTIRE THING SHOULD BE RE-WRITTEN IN ANOTHER LANGUAGE))
# 
#
# (A side note, you'll notice that in various locations throughout this script I use "touch" 
# to create a file before it's used, not always but sometimes. These are generally for a 
# reason; many of the shell utilities being called will not directly output to a non existent
# file with ">" this is generally do to how they handle standard i/o. So if you make 
# modifications to this script please do not take them out, you'll end up with errors)
#
# Script Assumes:
# 1.) You are running as root - else exit
# 2.) You do not have the log directories or anything in them already - else exit
# 3.) You have snort and suricata installed and configured already
# 4.) You are using the defined Directory Structure
# 5.) You have all the config files listed and in the correct place
# 6.) You have all the rule packs listed and in the right place
#
# It should be noted that since we're only measuring the process ID specified in pidstat
# we don't need to worry about results being skewed by running this script.
#
# Version: v15
#
# Revision Control:
#
# 	Version 1: Supported Creating a PidStat Log From Suricata
#
#	Version 2: Supported Creating a PidStat Log and CSV From Suricata
#
#	Version 3: Supported Creating a PidStat Log and CSV as well as a Packets Per Minute Log all for Suricata
#
#	Version 4: Same as V.3 but also added support for creating a PidStat Log and CSV for Snort (no snort pps csv yet)
#
#	Version 5: Same as V.3 but now with snort PPS processing and output to CSV
#
#	Version 6: Same as V.5 but I've added calculation of max min average for PPS (both snort and suricata, I'm pushing GNU-PLOT off to next version
#
#	Version 7: This was a big revision, I stabilized pidstat command to get true 1 second intervals, 
#                                           added time conversion for everything, 
#                                           fixed a bunch of bugs,
#                                           added a useful summary logfile
#
#	Version 8: This version adds: 	Turned tests into one massive ugly function
#					Calls that function twice, once for testing with Emerging Threats Rules and Once Without
#					Output is not in two directories, one for rule based tests and one without
#					Still need to replace pidstat with ps, need to update process log script and add to this, need to add options menu (tests, or process logs) 
#
#	Version 9: This version adds:	Started adding support for running for additional PCAP Files based on individual Pytbull Captures (not finished)
#					Additional Runs for other Suricata / Snort Config Files (No-Rules/ET_Free-Rules/ET_Pro-Rules/VRT_Free-Rules) as well as (Optimized Suricata for Multi Core)
#					Adds command line options section
#					Adds option for running same tests multiple times and getting the standard deviation.
# 					Variables Are Now Defined for output files instead of hard-coded
#					Added Final Log Parsing Capability as a function that can be called with command line option
#					Added ~250 Lines, Removed ~100 Lines, Turned all instances of Min/Max/Mean into single function
#					Still should have average/min/max calculations turned into a separate function but they work as is (just extra junk code)
#
#	Version 10: This version adds:	-r option for shorter but more comprehensive no-rules tests.
#					This was a quick mod version since I wasn't ready to run all tests (log file formats were not established yet) next version will fix all other issues with luck
#
#	Version 11: This version adds:	Fixes the run all tests now changed to -a
#					Adds new master log file output
#					We're at 1300+ lines to this script, the next revision is going to need some cleanup to get rid of unnecessary junk that got left in during testing but then commented out
#					This version corrects the labeling issue for the STD_Dev_Logs Function that was giving us reversed SNORT / SURICATA labels
#					This version includes fixed labels that had previously been screwing up our graphs
#					This version adds -p option for creating a master log output directory after you have run the script on 10 different core configurations
#					This version adds calculation of standard deviations for cores used, and memory used
#					This version does not add calculation of packet loss... (No point in calculating it if we're reading a PCap, the engines will only read at a rate they can handle)
#					This version also adds output to the standard deviation logs for Time Spent (in Sseconds) for total engine processing.
#					Next version also is going to need a full readme, and include instructions for downloading rules, and eventually we're going to need to either include:
#						- a set of suricata.yaml and snort.cfg's (not sure about licensing on that one) or
#						- the other option is to create a patch functions that will change the necessary lines in the config files
#					We're now using the following PCaps
#						-rw-r--r--. 1 root root  64M Dec  2 10:18 pytbull_ALL.pcap
#						-rw-r--r--. 1 root root 3.8M Dec  2 10:25 pytbull_badTraffic.pcap
#						-rw-r--r--. 1 root root 6.2M Dec  2 10:23 pytbull_clientSideAttacks.pcap
#						-rw-r--r--. 1 root root 2.4M Dec  2 10:44 pytbull_DOS.pcap
#						-rw-r--r--. 1 root root  22M Dec  2 10:39 pytbull_evasionTechniques.pcap
#						-rw-r--r--. 1 root root 4.4M Dec  2 10:29 pytbull_fragmentedPackets.pcap
#						-rw-r--r--. 1 root root 1.9M Dec  2 10:32 pytbull_multipleFailedLogins.pcap
#						-rw-r--r--. 1 root root 2.3M Dec  2 10:45 pytbull_replay.pcap
#						-rw-r--r--. 1 root root  16M Dec  2 10:43 pytbull_shellCodes.pcap
#						-rw-r--r--. 1 root root  26M Dec  2 10:24 pytbull_testRules.pcap
#					For now -p option to process log files after all core runs have finished is disabled, I need to do more error checking so we don't have another misslabeling occur, I'll do this after the next round of tests
#
#	Version 12: Some Minor fixes and inclusion of some of the -p log file creation
#
#	Version 13: Added tweeked suricata config tests and more log file processing and -c option for creating initial directories
#					It's worth mentioning that "TWEEKED" refers to Suricata with AUTOFP 
#
#	Version 14: MAJOR FIX - Fixed Issue with PPS final log grabbing in Suricata, we were pulling form the wrong column which caused inacurate max and average PPS
#
#	Version 15: MAJOR ADD - Added Generation of CSV's for Final Plotting -G option
#
# whitejs@clarkson.edu

### Left in for error handling ###
#echo "starting"
#set -v on
#set -x on


#################
### Settings  ###
#################

     # Define your pcap file location here:
     PCAP_FILE=""
     PCAP_FILE_LARGE_TEST="/mnt/ictf2010.pcap"
     PCAP_FILE_PytBull_1="/mnt/pytbull_pcaps/pytbull_badTraffic.pcap"
     PCAP_FILE_PytBull_2="/mnt/pytbull_pcaps/pytbull_clientSideAttacks.pcap"
     PCAP_FILE_PytBull_3="/mnt/pytbull_pcaps/pytbull_DOS.pcap"
     PCAP_FILE_PytBull_4="/mnt/pytbull_pcaps/pytbull_evasionTechniques.pcap"
     PCAP_FILE_PytBull_5="/mnt/pytbull_pcaps/pytbull_fragmentedPackets.pcap"
     PCAP_FILE_PytBull_6="/mnt/pytbull_pcaps/pytbull_multipleFailedLogins.pcap"
     PCAP_FILE_PytBULL_7="/mnt/pytbull_pcaps/pytbull_replay.pcap"
     PCAP_FILE_PytBull_8="/mnt/pytbull_pcaps/pytbull_shellCodes.pcap"
     PCAP_FILE_PytBull_9="/mnt/pytbull_pcaps/pytbull_testRules.pcap"     
     PCAP_FILE_PytBull_ALL="/mnt/pytbull_pcaps/pytbull_ALL.pcap"

     # Define your suricata configs here:
     SURICATA_CONFIG="default"
     SURICATA_CONFIG_NO_RULES="/etc/suricata/suricata.yaml_no_rules"
     SURICATA_CONFIG_NO_RULES_TWEEKED_FOR_MULTI_CORE="/etc/suricata/suricata.yaml_no_rules_suricata_multi_core_tweeked"
     SURICATA_CONFIG_ET_FREE_RULES="/etc/suricata/suricata.yaml_et_free"
     SURICATA_CONFIG_ET_FREE_RULES_TWEEKED="/etc/suricata/suricata.yaml_et_free_tweeked"
     SURICATA_CONFIG_ET_PRO_RULES="/etc/suricata/suricata.yaml_et_pro"
     SURICATA_CONFIG_ET_PRO_RULES_TWEEKED="/etc/suricata/suricata.yaml_et_pro_tweeked"
     SURICATA_CONFIG_VRT_FREE_RULES="/etc/suricata/suricata.yaml_vrt"
     SURICATA_CONFIG_VRT_FREE_RULES_TWEEKED="/etc/suricata/suricata.yaml_vrt_tweeked"

     # Define your snort configs here:
     SNORT_CONFIG="default"
     SNORT_CONFIG_NO_RULES="/etc/snort/snort.conf_no_rules"
     SNORT_CONFIG_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE="/etc/snort/snort.conf_no_rules_suricata_multi_core_tweeked"
     SNORT_CONFIG_ET_FREE_RULES="/etc/snort/snort.conf_et_free"
     SNORT_CONFIG_ET_FREE_RULES_TWEEKED="/etc/snort/snort.conf_et_free_tweeked"
     SNORT_CONFIG_ET_PRO_RULES="/etc/snort/snort.conf_et_pro"
     SNORT_CONFIG_ET_PRO_RULES_TWEEKED="/etc/snort/snort.conf_et_pro_tweeked"
     SNORT_CONFIG_VRT_FREE_RULES="/etc/snort/snort.conf_vrt"
     SNORT_CONFIG_VRT_FREE_RULES_TWEEKED="/etc/snort/snort.conf_vrt_tweeked"

     # Define your random settings here:
     SAMPLING_TIME=120 #in seconds
     MAX_LOG_DURATION=4000 #in seconds
     LOG_INTERVAL=1 #in seconds
     OUTPUT_DIRECTORY="tests_output"
     IDS_COMPARISON_TESTING_LOG="run.log"
     VERSION="Version 15"

     # Define your output files directory here:
     SURICATA_PROCESS_STATS_CSV="default"
     SURICATA_PROCESS_STATS_CSV_NO_RULES="process-suricata-stats_no_rules.csv"
     SURICATA_PROCESS_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE="process-suricata-stats_no_rules_suricta_multi_core_tweeked.csv"
     SURICATA_PROCESS_STATS_CSV_ET_FREE_RULES="process-suricata-stats_et_free_rules.csv"
     SURICATA_PROCESS_STATS_CSV_ET_FREE_RULES_TWEEKED="process-suricata-stats_et_free_rules_tweeked.csv"
     SURICATA_PROCESS_STATS_CSV_ET_PRO_RULES="process-suricata-stats_et_pro_rules.csv"
     SURICATA_PROCESS_STATS_CSV_ET_PRO_RULES_TWEEKED="process-suricata-stats_et_pro_rules_tweeked.csv"
     SURICATA_PROCESS_STATS_CSV_VRT_FREE_RULES="process-suricata-stats_vrt_rules.csv"
     SURICATA_PROCESS_STATS_CSV_VRT_FREE_RULES_TWEEKED="process-suricata-stats_vrt_rules_tweeked.csv"

     SURICATA_STATS_CSV="default"
     SURICATA_STATS_CSV_NO_RULES="suricata-stats_no_rules.csv"
     SURICATA_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE="suricata-stats_no_rules_suricata_multi_core_tweeked.csv"
     SURICATA_STATS_CSV_ET_FREE_RULES="suricata-stats_et_free_rules.csv"
     SURICATA_STATS_CSV_ET_PRO_RULES="suricata-stats_et_pro_rules.csv"
     SURICATA_STATS_CSV_VRT_FREE_RULES="suricata-stats_vrt_rules.csv"
     SURICATA_STATS_CSV_ET_FREE_RULES_TWEEKED="suricata-stats_et_free_rules_tweeked.csv"
     SURICATA_STATS_CSV_ET_PRO_RULES_TWEEKED="suricata-stats_et_pro_rules_tweeked.csv"
     SURICATA_STATS_CSV_VRT_FREE_RULES_TWEEKED="suricata-stats_vrt_rules_tweeked.csv"

     SNORT_PROCESS_STATS_CSV="default"
     SNORT_PROCESS_STATS_CSV_NO_RULES="process-snort-stats_no_rules.csv"
     SNORT_PROCESS_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE="process-snort-stats_no_rules_suricata_multi_core_tweeked.csv"
     SNORT_PROCESS_STATS_CSV_ET_FREE_RULES="process-snort-stats_et_free_rules.csv"
     SNORT_PROCESS_STATS_CSV_ET_PRO_RULES="process-snort-stats_et_pro_rules.csv"
     SNORT_PROCESS_STATS_CSV_VRT_FREE_RULES="process-snort-stats_vrt_rules.csv"
     SNORT_PROCESS_STATS_CSV_ET_FREE_RULES_TWEEKED="process-snort-stats_et_free_rules_tweeked.csv"
     SNORT_PROCESS_STATS_CSV_ET_PRO_RULES_TWEEKED="process-snort-stats_et_pro_rules_tweeked.csv"
     SNORT_PROCESS_STATS_CSV_VRT_FREE_RULES_TWEEKED="process-snort-stats_vrt_rules_tweeked.csv"

     SNORT_STATS_CSV="default"
     SNORT_STATS_CSV_NO_RULES="snort-stats_no_rules.csv" 
     SNORT_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE="snort-stats_no_rules_suricata_multi_core_tweeked.csv"
     SNORT_STATS_CSV_ET_FREE_RULES="snort-stats_et_free_rules.csv"
     SNORT_STATS_CSV_ET_PRO_RULES="snort-stats_et_pro_rules.csv"
     SNORT_STATS_CSV_VRT_FREE_RULES="snort-stats_vrt_rules.csv"
     SNORT_STATS_CSV_ET_FREE_RULES_TWEEKED="snort-stats_et_free_rules_tweeked.csv"
     SNORT_STATS_CSV_ET_PRO_RULES_TWEEKED="snort-stats_et_pro_rules_tweeked.csv"
     SNORT_STATS_CSV_VRT_FREE_RULES_TWEEKED="snort-stats_vrt_rules_tweeked.csv"
     
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

     OUTPUT_LOG_DIRECTORY="all_runs_summary_logs_output"
     INDIVIDUAL_TESTS_LOG_DIRECTORY=""
     INDIVIDUAL_TESTS_LOG_DIRECTORY_NO_RULES="test_output_no_rules"
     INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_FREE_RULES="test_output_et_free_rules"
     INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_PRO_RULES="test_output_et_pro_rules"
     INDIVIDUAL_TESTS_LOG_DIRECTORY_NO_RULES_SURICATA_OPTOMIZED="test_output_no_rules_tweeked"
     INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_FREE_RULES_SURICATA_OPTOMIZED="test_output_et_free_rules_tweeked"
     INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_PRO_RULES_SURICATA_OPTOMIZED="test_output_et_pro_rules_tweeked"
     INDIVIDUAL_TESTS_LOG_DIRECTORY_VRT_FREE_RULES="test_output_vrt_free_rules"
     INDIVIDUAL_TESTS_LOG_DIRECTORY_VRT_FREE_RULES_SURICATA_OPTOMIZED="test_output_vrt_free_rules_tweeked"

     SYSTEM_CONFIG_DIR=""
     SYSTEM_CONFIG_DIR_1="1cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_2="2cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_3="3cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_4="4cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_5="5cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_6="6cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_7="8cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_8="12cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_9="18cpu_48g-std-t1"
     SYSTEM_CONFIG_DIR_10="24cpu_48g-std-t1"

     PCAP_SUB_DIR=""
     PCAP_SUB_DIR1="ictf2010pcap_based_runs"
     PCAP_SUB_DIR2="pytbull_allpcap_based_runs"
     PCAP_SUB_DIR3="pytbull_t1pcap_based_run"
     PCAP_SUB_DIR4="pytbull_t2pcap_based_runs"
     PCAP_SUB_DIR5="pytbull_t3pcap_based_runs"
     PCAP_SUB_DIR6="pytbull_t4pcap_based_runs"
     PCAP_SUB_DIR7="pytbull_t5pcap_based_runs"
     PCAP_SUB_DIR8="pytbull_t6pcap_based_runs"
     PCAP_SUB_DIR9="pytbull_t7pcap_based_runs"
     PCAP_SUB_DIR10="pytbull_t8pcap_based_runs"
     PCAP_SUB_DIR11="pytbull_t9pcap_based_runs"

     PCAP_TYPES=""
     PCAP_TYPES_1="ictf"
     PCAP_TYPES_2="pytbull_allpcap_based_runs"
     PCAP_TYPES_3="pytbull_t1pcap_based_run"
     PCAP_TYPES_4="pytbull_t2pcap_based_runs"
     PCAP_TYPES_5="pytbull_t3pcap_based_runs"
     PCAP_TYPES_6="pytbull_t4pcap_based_runs"
     PCAP_TYPES_7="pytbull_t5pcap_based_runs"
     PCAP_TYPES_8="pytbull_t6pcap_based_runs"
     PCAP_TYPES_9="pytbull_t7pcap_based_runs"
     PCAP_TYPES_10="pytbull_t8ocap_based_runs"
     PCAP_TYPES_11="pytbull_t9pcap_based_runs"


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

	SNORT v. SURICATA - Measurement and Analysis System

				 ##############################################
                                 #                                            #
				 #  CCCCCC CCCCCCC   CCCCCCC CC   CC CC   CC  #
				 #  CC     CC        CC      CC   CC CC   CC  #
				 #  CC      CCCCC    CCCCCCC CCCCCCC CCCCCCC  #
				 #  CC          CC   CC   CC      CC      CC  #
				 #  CCCCCC CCCCCCC   CCCCCCC      CC      CC  #
                                 #                                            #
                                 ##############################################

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

	   -c	   Create the Initial Directory Structure

           -h / -? Show this message

           -t      Runs the tests with the preconfigured pcaps, output is 5 directories containing csv's
		   each directory has a summary log file included in it. These tests are done with no rules
		   enabled in either Suricata or Snort. The test is really just to gauge raw performance with
		   no special features / or addons.

	   -a	   Runs all tests (like -t) but also calculates Std Deviations In Final Log, in addition this tests
		   multiple rulesets and configurations (No Rules) (VRT Free) (ET Free) (ET Pro) 
		   and (Tweeked Suricata for Multi-Core with all 4 rule configurations)
		   ((BE AWARE!: This option takes around 2 hours to run on a 24 Core Configuration))

           -p      Process the logs to create a single master log (this needs updating)
		   This is used after you have completed running -a on each of the 10 system configurations:
		   (System Configurations Include: 1cpu, 2cpu, 3cpu, 4cpu, 5cpu, 6cpu, 8cpu, 12cpu, 18cpu, 24cpu all with 48GB of RAM)

	   -g	   This option generates the CSV's needed (in the correct format for Excel/Libre-Office Calc/Google Office) to Graph 
		   the items we currently care about for the final paper.
		      Memory Versus Workload (1,4,24) Core Configurations for Suricata (1) Core Configuration for Snort

           -s      Specifiy a PCap file like (-s test.pcap) 
		   After a pcap is chosen -t is automatically run

	   -v	   Prints Version Information

	   -r      Runs 5 instances of Snort / Suricata Tests without rules and calculates output with standard deviation (used for testing)

	Example Usage:

	  Run tests using specified PCap:
	    $0 -s test.pcap 

	  Run all tests using 7 predefined pcaps:
	    $0 -t

	  Run absolutly all tests possible (This takes a very long time)
	    $0 -a
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
		    paste temp3.file temp2.file | sed 's/\t/,/g' | uniq | awk 'BEGIN {FS=OFS=","}{$3=$2*100}1' >> $SNORT_STATS_CSV

		    # clean up and get read to start over
		    rm -f out.* temp*.file

     ##########################
     ### Create the Run Log ###
     ##########################

           # Setup the logfile headers
           echo "IDS Name,PCAP Name,Total Process Time (Sec),Total Run Time (Sec),Min # CPU,Max # CPU,AVG # CPU, Min % CPU,Max % CPU,Avg % CPU,Min RSS (KB),Max RSS (KB),Avg RSS (KB), Min % Mem,Max % Mem,Avg % Mem,Min PPS,Max PPS,Avg PPS" > $IDS_COMPARISON_TESTING_LOG

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

     ######################################################################################################
     ### This isn't all that needed but I prefer to keep these logs in their original form just in case ###
     ######################################################################################################

     cp /var/log/suricata/stats.log $OUTPUT_DIRECTORY
     cp /var/log/snort/snort.stats $OUTPUT_DIRECTORY

     ###############
     ### Cleanup ###
     ###############

     rm -rf temp*.file

  done
##############################################
### End the Run Test Big and Ugly function ###
##############################################
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

##############################################################
########### Create the Standard Deviation Log File ###########
##############################################################

# This creates the master tests_run log file for this round of tests
function STD_DEV_PROCESSLOGFILES {

### This first section process the logs to get avg, stdev of PPS for each run ###
rm -rf temp*.file

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

echo "Suricata - Standard Deviations All Runs PPS" >> temp4.file
TEMP_FILE=temp2.file
CALCULATE_TESTS_STD_DEVIATION >> temp4.file

echo "Snort - Standard Deviations All Runs PPS" >> temp5.file
TEMP_FILE=temp1.file
CALCULATE_TESTS_STD_DEVIATION >> temp5.file 

cat temp4.file >> $STD_LOG_NAME
cat temp5.file >> $STD_LOG_NAME

rm -rf temp*.file

### This second section does the same as the previous but this time to grab core utilization

cat 1/$LOG_NAME | grep snort | cut -d, -f 10 >> temp1.file
cat 2/$LOG_NAME | grep snort | cut -d, -f 10 >> temp1.file
cat 3/$LOG_NAME | grep snort | cut -d, -f 10 >> temp1.file
cat 4/$LOG_NAME | grep snort | cut -d, -f 10 >> temp1.file
cat 5/$LOG_NAME | grep snort | cut -d, -f 10 >> temp1.file

cat 1/$LOG_NAME | grep suricata | cut -d, -f 10 >> temp2.file
cat 2/$LOG_NAME | grep suricata | cut -d, -f 10 >> temp2.file
cat 3/$LOG_NAME | grep suricata | cut -d, -f 10 >> temp2.file
cat 4/$LOG_NAME | grep suricata | cut -d, -f 10 >> temp2.file
cat 5/$LOG_NAME | grep suricata | cut -d, -f 10 >> temp2.file

echo "Suricata - Standard Deviations All Runs Core Utilization (%)" >> temp4.file
TEMP_FILE=temp2.file
CALCULATE_TESTS_STD_DEVIATION >> temp4.file

echo "Snort - Standard Deviations All Runs Core Utilization (%)" >> temp5.file
TEMP_FILE=temp1.file
CALCULATE_TESTS_STD_DEVIATION >> temp5.file 

cat temp4.file >> $STD_LOG_NAME
cat temp5.file >> $STD_LOG_NAME

rm -rf temp*.file

### This third section does the same as the previous but this time for memory usage

cat 1/$LOG_NAME | grep snort | cut -d, -f 13 >> temp1.file
cat 2/$LOG_NAME | grep snort | cut -d, -f 13 >> temp1.file
cat 3/$LOG_NAME | grep snort | cut -d, -f 13 >> temp1.file
cat 4/$LOG_NAME | grep snort | cut -d, -f 13 >> temp1.file
cat 5/$LOG_NAME | grep snort | cut -d, -f 13 >> temp1.file

cat 1/$LOG_NAME | grep suricata | cut -d, -f 13 >> temp2.file
cat 2/$LOG_NAME | grep suricata | cut -d, -f 13 >> temp2.file
cat 3/$LOG_NAME | grep suricata | cut -d, -f 13 >> temp2.file
cat 4/$LOG_NAME | grep suricata | cut -d, -f 13 >> temp2.file
cat 5/$LOG_NAME | grep suricata | cut -d, -f 13 >> temp2.file

echo "Suricata - Standard Deviations All Runs Memory Usage in (KB)" >> temp4.file
TEMP_FILE=temp2.file
CALCULATE_TESTS_STD_DEVIATION >> temp4.file

echo "Snort - Standard Deviations All Runs Memory Usage (KB)" >> temp5.file
TEMP_FILE=temp1.file
CALCULATE_TESTS_STD_DEVIATION >> temp5.file 

cat temp4.file >> $STD_LOG_NAME
cat temp5.file >> $STD_LOG_NAME

rm -rf temp*.file

### This forth section does the same as the previous 3 but this time for run time averages and standard deviations

cat 1/$LOG_NAME | grep snort | cut -d, -f 4 >> temp1.file
cat 2/$LOG_NAME | grep snort | cut -d, -f 4 >> temp1.file
cat 3/$LOG_NAME | grep snort | cut -d, -f 4 >> temp1.file
cat 4/$LOG_NAME | grep snort | cut -d, -f 4 >> temp1.file
cat 5/$LOG_NAME | grep snort | cut -d, -f 4 >> temp1.file

cat 1/$LOG_NAME | grep suricata | cut -d, -f 4 >> temp2.file
cat 2/$LOG_NAME | grep suricata | cut -d, -f 4 >> temp2.file
cat 3/$LOG_NAME | grep suricata | cut -d, -f 4 >> temp2.file
cat 4/$LOG_NAME | grep suricata | cut -d, -f 4 >> temp2.file
cat 5/$LOG_NAME | grep suricata | cut -d, -f 4 >> temp2.file

echo "Suricata - Standard Deviations All Runs - Run Time (Seconds)" >> temp4.file
TEMP_FILE=temp2.file
CALCULATE_TESTS_STD_DEVIATION >> temp4.file

echo "Snort - Standard Deviations All Runs - Run Time (Seconds)" >> temp5.file
TEMP_FILE=temp1.file
CALCULATE_TESTS_STD_DEVIATION >> temp5.file 

cat temp4.file >> $STD_LOG_NAME
cat temp5.file >> $STD_LOG_NAME

rm -rf temp*.file


### End of Function ###

}

##############################################
########### Run All Tests Function ###########
##############################################

function RUN_ALL_TESTS {

  ####################################
  ### Tests With No Rules Included ###
  ####################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_NO_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_NO_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_NO_RULES

  SNORT_CONFIG=$SNORT_CONFIG_NO_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_NO_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_NO_RULES

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_no_rules/
  mv 1 test_output_no_rules/
  mv 2 test_output_no_rules/
  mv 3 test_output_no_rules/
  mv 4 test_output_no_rules/
  mv 5 test_output_no_rules/
  mv std_run_log test_output_no_rules/

  ###########################################################
  ### Tests With No Rules Included And Suricata Optomized ###
  ###########################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_NO_RULES_TWEEKED_FOR_MULTI_CORE
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_NO_RULES_TWEEKED_FOR_MULTI_CORE

  SNORT_CONFIG=$SNORT_CONFIG_NO_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE
  SNORT_STATS_CSV=$SNORT_STATS_CSV_NO_RULES_W_SURICATA_TWEEKED_FOR_MULTI_CORE

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_no_rules_tweeked/
  mv 1 test_output_no_rules_tweeked/
  mv 2 test_output_no_rules_tweeked/
  mv 3 test_output_no_rules_tweeked/
  mv 4 test_output_no_rules_tweeked/
  mv 5 test_output_no_rules_tweeked/
  mv std_run_log test_output_no_rules_tweeked/

  #########################################
  ### Tests With ET Free Rules Included ###
  #########################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_ET_FREE_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_ET_FREE_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_ET_FREE_RULES

  SNORT_CONFIG=$SNORT_CONFIG_ET_FREE_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_ET_FREE_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_ET_FREE_RULES

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_et_free_rules/
  mv 1 test_output_et_free_rules/
  mv 2 test_output_et_free_rules/
  mv 3 test_output_et_free_rules/
  mv 4 test_output_et_free_rules/
  mv 5 test_output_et_free_rules/
  mv std_run_log test_output_et_free_rules/

  ################################################################
  ### Tests With ET Free Rules Included and Suricata Optomized ###
  ################################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_ET_FREE_RULES_TWEEKED
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_ET_FREE_RULES_TWEEKED
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_ET_FREE_RULES_TWEEKED

  SNORT_CONFIG=$SNORT_CONFIG_ET_FREE_RULES_TWEEKED
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_ET_FREE_RULES_TWEEKED
  SNORT_STATS_CSV=$SNORT_STATS_CSV_ET_FREE_RULES_TWEEKED

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_et_free_rules_tweeked/
  mv 1 test_output_et_free_rules_tweeked/
  mv 2 test_output_et_free_rules_tweeked/
  mv 3 test_output_et_free_rules_tweeked/
  mv 4 test_output_et_free_rules_tweeked/
  mv 5 test_output_et_free_rules_tweeked/
  mv std_run_log test_output_et_free_rules_tweeked/


  ########################################
  ### Tests With ET Pro Rules Included ###
  ########################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_ET_PRO_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_ET_PRO_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_ET_PRO_RULES

  SNORT_CONFIG=$SNORT_CONFIG_ET_PRO_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_ET_PRO_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_ET_PRO_RULES

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_et_pro_rules/
  mv 1 test_output_et_pro_rules/
  mv 2 test_output_et_pro_rules/
  mv 3 test_output_et_pro_rules/
  mv 4 test_output_et_pro_rules/
  mv 5 test_output_et_pro_rules/
  mv std_run_log test_output_et_pro_rules/

  ################################################################
  ### Tests With ET Pro Rules Included with Suricata Optomized ###
  ################################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_ET_PRO_RULES_TWEEKED
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_ET_PRO_RULES_TWEEKED
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_ET_PRO_RULES_TWEEKED

  SNORT_CONFIG=$SNORT_CONFIG_ET_PRO_RULES_TWEEKED
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_ET_PRO_RULES_TWEEKED
  SNORT_STATS_CSV=$SNORT_STATS_CSV_ET_PRO_RULES_TWEEKED

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_et_pro_rules_tweeked/
  mv 1 test_output_et_pro_rules_tweeked/
  mv 2 test_output_et_pro_rules_tweeked/
  mv 3 test_output_et_pro_rules_tweeked/
  mv 4 test_output_et_pro_rules_tweeked/
  mv 5 test_output_et_pro_rules_tweeked/
  mv std_run_log test_output_et_pro_rules_tweeked/

  ##########################################
  ### Tests With VRT Free Rules Included ###
  ##########################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_VRT_FREE_RULES
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_VRT_FREE_RULES
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_VRT_FREE_RULES

  SNORT_CONFIG=$SNORT_CONFIG_VRT_FREE_RULES
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_VRT_FREE_RULES
  SNORT_STATS_CSV=$SNORT_STATS_CSV_VRT_FREE_RULES

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_vrt_rules/
  mv 1 test_output_vrt_rules/
  mv 2 test_output_vrt_rules/
  mv 3 test_output_vrt_rules/
  mv 4 test_output_vrt_rules/
  mv 5 test_output_vrt_rules/
  mv std_run_log test_output_vrt_rules/

  #################################################################
  ### Tests With VRT Free Rules Included and Suricata Optomized ###
  #################################################################

  # Sets up variables for this round of tests
  SURICATA_CONFIG=$SURICATA_CONFIG_VRT_FREE_RULES_TWEEKED
  SURICATA_PROCESS_STATS_CSV=$SURICATA_PROCESS_STATS_CSV_VRT_FREE_RULES_TWEEKED
  SURICATA_STATS_CSV=$SURICATA_STATS_CSV_VRT_FREE_RULES_TWEEKED

  SNORT_CONFIG=$SNORT_CONFIG_VRT_FREE_RULES_TWEEKED
  SNORT_PROCESS_STATS_CSV=$SNORT_PROCESS_STATS_CSV_VRT_FREE_RULES_TWEEKED
  SNORT_STATS_CSV=$SNORT_STATS_CSV_VRT_FREE_RULES_TWEEKED

  # Runs Tests
  RUNTESTS

  # Get the stanard deviation for PPS and create the log file for it
  STD_DEV_PROCESSLOGFILES

  # create an output subdirector and move everything to it before running next round of tests
  mkdir test_output_vrt_rules_tweeked/
  mv 1 test_output_vrt_rules_tweeked/
  mv 2 test_output_vrt_rules_tweeked/
  mv 3 test_output_vrt_rules_tweeked/
  mv 4 test_output_vrt_rules_tweeked/
  mv 5 test_output_vrt_rules_tweeked/
  mv std_run_log test_output_vrt_rules_tweeked/

  #################################
  ### Run the Pass Log Function ###
  #################################

#  PROCESS_ALL_PASS_LOGS

##################################
### End Run All Tests Function ###
##################################

}

#########################################################################
########### Process Log Files - Another Big and Ugly Function ###########
#########################################################################

### The next 300+ lines needs to eventually be turned it to a loop for efficiency and code reduction

function PROCESSLOGFILES {

INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_FREE_RULES
PROCESSLOGFILES_SUB_FUNCTION

INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_FREE_RULES_SURICATA_OPTOMIZED
PROCESSLOGFILES_SUB_FUNCTION

INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_PRO_RULES
PROCESSLOGFILES_SUB_FUNCTION

INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_NO_RULES
PROCESSLOGFILES_SUB_FUNCTION

INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_NO_RULES_SURICATA_OPTOMIZED
PROCESSLOGFILES_SUB_FUNCTION

}

function PROCESSLOGFILES_SUB_FUNCTION {

rm -rf temp*.file

cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file 
cat 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done 

echo "Test Run," >> temp4.file
echo "1," >> temp4.file 
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 1cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 2cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 3cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 4cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 5cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 6cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 8cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 12cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 18cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp1.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep suricata >> temp1.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep suricata >> temp1.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep suricata >> temp1.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep suricata >> temp1.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep suricata >> temp1.file

cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep IDS > temp2.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/1/run.log | grep snort >> temp2.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/2/run.log | grep snort >> temp2.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/3/run.log | grep snort >> temp2.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/4/run.log | grep snort >> temp2.file
cat 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/5/run.log | grep snort >> temp2.file

N=1
loops=7

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

echo "Test Run," >> temp4.file
echo "1," >> temp4.file
echo "2," >> temp4.file
echo "3," >> temp4.file
echo "4," >> temp4.file
echo "5," >> temp4.file

paste temp4.file temp2.file temp3.file temp1.file >> 24cpu_48g-std-complete-runs_summary.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY

rm -f temp*.file

mkdir all_runs_summary_logs_output
mv *.log all_runs_summary_logs_output
cp 1cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/1cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 2cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/2cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 3cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/3cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 4cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/4cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 5cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/5cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 6cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/6cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 8cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/8cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 12cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/12cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 18cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/18cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY
cp 24cpu_48g-std-t1/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log all_runs_summary_logs_output/24cpu_48g-std-complete_std-run.log_$INDIVIDUAL_TESTS_LOG_DIRECTORY



####################################
### END PROCESSLOGFILES FUNCTION ###
####################################

}

###################################################################################################
########### Process the final end of study log files, must have all directories present ###########
###################################################################################################

function PROCESS_FINAL_STUDY_LOGS {

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_1

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_2

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_3

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_4

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_5

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_6

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_7

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_8

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_9

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

SYSTEM_CONFIG_DIR=$SYSTEM_CONFIG_DIR_10

  GET_STDEV_LOG_DATA_SET_PCAP_PARM

}

### Final Log Gathering and Assmembly - Function 1 - This one sets the pcap directory paramerters ###

function GET_STDEV_LOG_DATA_SET_PCAP_PARM {

  PCAP_SUB_DIR=$PCAP_SUB_DIR1

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR2

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR3

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR4

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR5

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR6

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR7

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR8

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR9

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR10

    GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA

  PCAP_SUB_DIR=$PCAP_SUB_DIR11

}

### Final Log Gathering and Assmembly - Function 2 - This one sets the test type directory paramerters ###

function GET_STDEV_LOG_DATA_SET_PARMS_GET_DATA {

    INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_FREE_RULES

      GET_STDEV_LOG_DATA_FOR_FINAL_CSV

    INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_FREE_RULES_SURICATA_OPTOMIZED

      GET_STDEV_LOG_DATA_FOR_FINAL_CSV

    INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_ET_PRO_RULES

      GET_STDEV_LOG_DATA_FOR_FINAL_CSV

    INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_NO_RULES

      GET_STDEV_LOG_DATA_FOR_FINAL_CSV

    INDIVIDUAL_TESTS_LOG_DIRECTORY=$INDIVIDUAL_TESTS_LOG_DIRECTORY_NO_RULES_SURICATA_OPTOMIZED

      GET_STDEV_LOG_DATA_FOR_FINAL_CSV

}

### Final Log Gathering and Assmembly - Function 3 - This does the actual data gathering and file output ###

function GET_STDEV_LOG_DATA_FOR_FINAL_CSV {
rm -rf temp*.file

echo $SYSTEM_CONFIG_DIR "," $PCAP_SUB_DIR "," $INDIVIDUAL_TESTS_LOG_DIRECTORY "," >> temp4.file

cat $SYSTEM_CONFIG_DIR/$PCAP_SUB_DIR/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log | sed '1d;/^[S]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d= -f 3 | cut -d, -f 1 > temp1.file
cat $SYSTEM_CONFIG_DIR/$PCAP_SUB_DIR/$INDIVIDUAL_TESTS_LOG_DIRECTORY/std_run_log | sed '1d;/^[S]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d= -f 4 > temp2.file

N=1
loops=9

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp3.file
  done

FILLTEMP=`paste temp1.file temp3.file temp2.file temp3.file`

echo $FILLTEMP >> temp5.file

paste temp4.file temp5.file >> almost_done_temp.file

}

function PROCESS_FINAL_STUDY_LOGS_ADD_CORE_COLUMN {

rm -rf temp*.file

echo "." >> temp1.file
echo "# OF CORES" >> temp1.file
echo "." >> temp1.file

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "1" >> temp1.file
  done

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "2" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "3" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "4" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "5" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "6" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "8" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "12" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "18" >> temp1.file
  done 

N=1
loops=51

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "24" >> temp1.file
  done 

N=1
loops=515

until [ "$N" -eq $loops ]
  do
    S1=$N
    ((S2=N+1))
    N=$S2
    echo "," >> temp2.file
  done

paste temp1.file temp2.file >> almost_done_temp_2.file

}

function MASTER_PROCESS_LOGS_FUNCTION {

cat alltests_final_summary_output.csv | grep $PCAP_TYPES | grep "test_output_et_free" >> temp1.file
cat alltests_final_summary_output.csv | grep $PCAP_TYPES | grep "test_output_et_pro" >> temp2.file
cat alltests_final_summary_output.csv | grep $PCAP_TYPES | grep "test_output_et_free_tweeked" >> temp7.file
cat alltests_final_summary_output.csv | grep $PCAP_TYPES | grep "test_output_no_rules " >> temp3.file
cat alltests_final_summary_output.csv | grep $PCAP_TYPES | grep "test_output_no_rules_tweeked" >> temp4.file

echo "
et_free # OF CORES, et_free SYSTEM CONFIGURATION, et_free TEST PCAP, et_free RULE CONFIGURATION,\
et_free Suricata PPS Average, et_free et_free Suricata PPS Stdev,\
et_free Snort PPS Average, et_free Snort PPS Stdev,\
et_free Suricata Core Utilization Average, et_free Suricata Core Utilization Stdev,\
et_free Snort Core Utilization Average, et_free Snort Core Utilization Stdev,\
et_free Suricata Memory Usage (KB) Average, et_free Suricata Memory Usage (KB) Stdev,\
et_free Snort Memory Usage (KB) Average, et_free Snort Memory Usage (KB) Stdev,\
et_free Suricata Run Time (Seconds) Average, et_free Suricata Run Time (Seconds) Standard Deviations,\
et_free Snort Run Time (Seconds) Average, et_free Snort Run Time (Seconds) Standard Deviations,\
et_pro # OF CORES,et_pro  SYSTEM CONFIGURATION,et_pro TEST PCAP,et_pro RULE CONFIGURATION,\
et_pro Suricata PPS Average,et_pro  Suricata PPS Stdev,\
et_pro Snort PPS Average,et_pro  Snort PPS Stdev,\
et_pro Suricata Core Utilization Average,et_pro  Suricata Core Utilization Stdev,\
et_pro Snort Core Utilization Average,et_pro  Snort Core Utilization Stdev,\
et_pro Suricata Memory Usage (KB) Average,et_pro  Suricata Memory Usage (KB) Stdev,\
et_pro Snort Memory Usage (KB) Average,et_pro  Snort Memory Usage (KB) Stdev,\
et_pro Suricata Run Time (Seconds) Average,et_pro  Suricata Run Time (Seconds) Standard Deviations,\
et_pro Snort Run Time (Seconds) Average,et_pro  Snort Run Time (Seconds) Standard Deviations,\
no_rules # OF CORES, SYSTEM CONFIGURATION,TEST PCAP,RULE CONFIGURATION,\
no_rules Suricata PPS Average,no_rules  Suricata PPS Stdev,\
no_rules Snort PPS Average,no_rules  Snort PPS Stdev,\
no_rules Suricata Core Utilization Average,no_rules  Suricata Core Utilization Stdev,\
no_rules Snort Core Utilization Average,no_rules  Snort Core Utilization Stdev,\
no_rules Suricata Memory Usage (KB) Average,no_rules  Suricata Memory Usage (KB) Stdev,\
no_rules Snort Memory Usage (KB) Average,no_rules  Snort Memory Usage (KB) Stdev,\
no_rules Suricata Run Time (Seconds) Average,no_rules  Suricata Run Time (Seconds) Standard Deviations,\
no_rules Snort Run Time (Seconds) Average,no_rules  Snort Run Time (Seconds) Standard Deviations,\
no_rules_tweeked # OF CORES,no_rules_tweeked  SYSTEM CONFIGURATION,no_rules_tweeked TEST PCAP,no_rules_tweeked RULE CONFIGURATION,\
no_rules_tweeked Suricata PPS Average,no_rules_tweeked  Suricata PPS Stdev,\
no_rules_tweeked Snort PPS Average,no_rules_tweeked  Snort PPS Stdev,\
no_rules_tweeked Suricata Core Utilization Average,no_rules_tweeked  Suricata Core Utilization Stdev,\
no_rules_tweeked Snort Core Utilization Average,no_rules_tweeked  Snort Core Utilization Stdev,\
no_rules_tweeked Suricata Memory Usage (KB) Average,no_rules_tweeked  Suricata Memory Usage (KB) Stdev,\
no_rules_tweeked Snort Memory Usage (KB) Average,no_rules_tweeked  Snort Memory Usage (KB) Stdev,\
no_rules_tweeked Suricata Run Time (Seconds) Average,no_rules_tweeked  Suricata Run Time (Seconds) Standard Deviations,\
no_rules_tweeked Snort Run Time (Seconds) Average,no_rules_tweeked  Snort Run Time (Seconds) Standard Deviations,
" > temp5.file

paste temp1.file temp7.file temp2.file temp3.file temp4.file > temp6.file

cat temp5.file > PCaps-Summary_log_.csv
cat temp6.file >> PCaps-Summary_log_.csv

rm -f temp*.file
}

function DASH_P_OPTION_END_OF_STUDY_LOG_BUILDING {

echo "
SYSTEM CONFIGURATION,TEST PCAP,RULE CONFIGURATION,\
Suricata PPS Average, Suricata PPS Stdev,\
Snort PPS Average, Snort PPS Stdev,\
Suricata Core Utilization Average, Suricata Core Utilization Stdev,\
Snort Core Utilization Average, Snort Core Utilization Stdev,\
Suricata Memory Usage (KB) Average, Suricata Memory Usage (KB) Stdev,\
Snort Memory Usage (KB) Average, Snort Memory Usage (KB) Stdev,\
Suricata Run Time (Seconds) Average, Suricata Run Time (Seconds) Standard Deviations,\
Snort Run Time (Seconds) Average, Snort Run Time (Seconds) Standard Deviations,
" > almost_done_temp.file

PROCESS_FINAL_STUDY_LOGS
PROCESS_FINAL_STUDY_LOGS_ADD_CORE_COLUMN
paste almost_done_temp_2.file almost_done_temp.file > alltests_final_summary_output.csv

rm -f temp*.file almost*

PCAP_TYPES=$PCAP_TYPES_1
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_2
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_3
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_4
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_5
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_6
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_7
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_8
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_9
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_10
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

PCAP_TYPES=$PCAP_TYPES_11
MASTER_PROCESS_LOGS_FUNCTION
mv PCaps-Summary_log_.csv "$PCAP_TYPES"_PCap-Summary_log.csv

}

function PLOTS_MEMORY_V_WORKLOAD {

rm PLOT_Core_Workloads_v_Memory_Usage.csv

############## Suricata 1 Core Config #############

echo "1 Core / All Workloads / All Rules Summary Sheet (SURICATA)," >> PLOT_Core_Workloads_v_Memory_Usage.csv
echo "TEST CATEGORY, SURICATA ET FREE RULES MEMORY USAGE, ET FREE MEMORY USAGE STANDARD DEVIATION, SURICATA ET FREE RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SURICATA ET-FREE MEMORY USAGE AUTO_FP 65K MAX PENDING STANDARD DEVIATION, SURICATA ET PRO MEMORY USAGE, SURICATA ET PRO MEMORY USAGE STANDARD DEVIATION, SURICATA NO RULES MEMORY USAGE, SURICATA NO RULES MEMORY USAGE STANDARD DEVIATION, SURICATA NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SURICATA NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING," >> PLOT_Core_Workloads_v_Memory_Usage.csv

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 > 181
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 > 182
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 > 183
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 > 184 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 > 185 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185                                       
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185

echo "," > 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180

paste 181 180 182 180 183 180 184 180 185 > 186.temp 

cat 186.temp >> PLOT_Core_Workloads_v_Memory_Usage.csv

rm -f 180 181 182 183 184 185 186.temp

echo " \
     " >> PLOT_Core_Workloads_v_Memory_Usage.csv

##############  SNORT 1 Core Config ##################

echo "1 Core / All Workloads / All Rules Summary Sheet (SNORT)," >> PLOT_Core_Workloads_v_Memory_Usage.csv
echo "TEST CATEGORY, SNORT ET FREE RULES MEMORY USAGE, ET FREE MEMORY USAGE STANDARD DEVIATION, SNORT ET FREE RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SNORT ET-FREE MEMORY USAGE AUTO_FP 65K MAX PENDING STANDARD DEVIATION, SNORT ET PRO MEMORY USAGE, SNORT ET PRO MEMORY USAGE STANDARD DEVIATION, SNORT NO RULES MEMORY USAGE, SNORT NO RULES MEMORY USAGE STANDARD DEVIATION, SNORT NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SNORT NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING," >> PLOT_Core_Workloads_v_Memory_Usage.csv

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 > 181
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep  "test_output_et_free_rules " | cut -d, -f 15,16 >> 181

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 > 182
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 15,16 >> 182

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 > 183
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep  "test_output_et_pro_rules " | cut -d, -f 15,16 >> 183

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 > 184 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep "test_output_no_rules " | cut -d, -f 15,16 >> 184 

cat alltests_final_summary_output.csv | grep "ictf" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 > 185 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185                                       
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep 1cpu | grep "test_output_no_rules_tweeked " | cut -d, -f 15,16 >> 185

echo "," > 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180

paste 181 180 182 180 183 180 184 180 185 > 186.temp 

cat 186.temp >> PLOT_Core_Workloads_v_Memory_Usage.csv

rm -f 180 181 182 183 184 185 186.temp

echo " \
     " >> PLOT_Core_Workloads_v_Memory_Usage.csv


########### SURICATA 4 Core Config ###########

echo "4 Core / All Workloads / All Rules Summary Sheet (SURICATA)," >> PLOT_Core_Workloads_v_Memory_Usage.csv
echo "TEST CATEGORY, SURICATA ET FREE RULES MEMORY USAGE, ET FREE MEMORY USAGE STANDARD DEVIATION, SURICATA ET FREE RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SURICATA ET-FREE MEMORY USAGE AUTO_FP 65K MAX PENDING STANDARD DEVIATION, SURICATA ET PRO MEMORY USAGE, SURICATA ET PRO MEMORY USAGE STANDARD DEVIATION, SURICATA NO RULES MEMORY USAGE, SURICATA NO RULES MEMORY USAGE STANDARD DEVIATION, SURICATA NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SURICATA NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING," >> PLOT_Core_Workloads_v_Memory_Usage.csv

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 > 181
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 > 182
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 > 183
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<4cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 > 184 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 > 185 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185                                       
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<4cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185

echo "," > 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180

paste 181 180 182 180 183 180 184 180 185 > 186.temp 

cat 186.temp >> PLOT_Core_Workloads_v_Memory_Usage.csv

rm -f 180 181 182 183 184 185 186.temp

echo " \
     " >> PLOT_Core_Workloads_v_Memory_Usage.csv

########### SURICATA 24 Core Config ###########

echo "24 Core / All Workloads / All Rules Summary Sheet (SURICATA)," >> PLOT_Core_Workloads_v_Memory_Usage.csv
echo "TEST CATEGORY, SURICATA ET FREE RULES MEMORY USAGE, ET FREE MEMORY USAGE STANDARD DEVIATION, SURICATA ET FREE RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SURICATA ET-FREE MEMORY USAGE AUTO_FP 65K MAX PENDING STANDARD DEVIATION, SURICATA ET PRO MEMORY USAGE, SURICATA ET PRO MEMORY USAGE STANDARD DEVIATION, SURICATA NO RULES MEMORY USAGE, SURICATA NO RULES MEMORY USAGE STANDARD DEVIATION, SURICATA NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING, SURICATA NO RULES MEMORY USAGE AUTO_FP 65K MAX PENDING," >> PLOT_Core_Workloads_v_Memory_Usage.csv

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 > 181
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules " | cut -d, -f 13,14 >> 181

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 > 182
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_free_rules_tweeked " | cut -d, -f 13,14 >> 182

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 > 183
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<24cpu_48g-std-t1\>' | grep  "test_output_et_pro_rules " | cut -d, -f 13,14 >> 183

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 > 184 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules " | cut -d, -f 13,14 >> 184 

cat alltests_final_summary_output.csv | grep "ictf" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 > 185 
cat alltests_final_summary_output.csv | grep "pytbull_t1" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185                                       
cat alltests_final_summary_output.csv | grep "pytbull_t2" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t3" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t4" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t5" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t6" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t8" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185  
cat alltests_final_summary_output.csv | grep "pytbull_t9" | grep -n -e '\<24cpu_48g-std-t1\>' | grep "test_output_no_rules_tweeked " | cut -d, -f 13,14 >> 185

echo "," > 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180
echo "," >> 180

paste 181 180 182 180 183 180 184 180 185 > 186.temp 

cat 186.temp >> PLOT_Core_Workloads_v_Memory_Usage.csv

rm -f 180 181 182 183 184 185 186.temp

echo " \
     " >> PLOT_Core_Workloads_v_Memory_Usage.csv


}

function PLOTS_PPS_V_NUMER_OF_CORES {

}

function PLOTS_CPU_UTILIZATION_V_WORKLOAD {

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
      exit 0

    else

      ################################
      ### Get Command Line Options ###
      ################################

    while getopts "rhtagpsvr" OPTION
    do
	case $OPTION in
	  c)
	      mkdir SYSTEM_CONFIG_DIR_1 SYSTEM_CONFIG_DIR_2 SYSTEM_CONFIG_DIR_3 SYSTEM_CONFIG_DIR_4 SYSTEM_CONFIG_DIR_5 SYSTEM_CONFIG_DIR_6 SYSTEM_CONFIG_DIR_7 SYSTEM_CONFIG_DIR_8 SYSTEM_CONFIG_DIR_9 SYSTEM_CONFIG_DIR_10 
	      ;;
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
	      RUN_TESTS
	      exit 1
	      ;;
	  a)
	      PCAP_FILE=$PCAP_FILE_LARGE_TEST
	      RUN_ALL_TESTS
	      mkdir ictf2010pcap_based_runs
	      mv test_output_et_free_rules ictf2010pcap_based_runs/
	      mv test_output_et_free_rules_tweeked ictf2010pcap_based_runs/
	      mv test_output_et_pro_rules ictf2010pcap_based_runs/
	      mv test_output_no_rules ictf2010pcap_based_runs/
	      mv test_output_no_rules_tweeked ictf2010pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_1
	      RUN_ALL_TESTS
	      mkdir pytbull_t1pcap_based_run
	      mv test_output_et_free_rules pytbull_t1pcap_based_run/
	      mv test_output_et_free_rules_tweeked pytbull_t1pcap_based_run/
	      mv test_output_et_pro_rules pytbull_t1pcap_based_run/
	      mv test_output_no_rules pytbull_t1pcap_based_run/
	      mv test_output_no_rules_tweeked pytbull_t1pcap_based_run/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_2
	      RUN_ALL_TESTS
	      mkdir pytbull_t2pcap_based_runs
	      mv test_output_et_free_rules pytbull_t2pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t2pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t2pcap_based_runs/
	      mv test_output_no_rules pytbull_t2pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t2pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_3
	      RUN_ALL_TESTS
	      mkdir pytbull_t3pcap_based_runs
	      mv test_output_et_free_rules pytbull_t3pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t3pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t3pcap_based_runs/
	      mv test_output_no_rules pytbull_t3pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t3pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_4
	      RUN_ALL_TESTS
	      mkdir pytbull_t4pcap_based_runs
	      mv test_output_et_free_rules pytbull_t4pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t4pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t4pcap_based_runs/
	      mv test_output_no_rules pytbull_t4pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t4pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_5
	      RUN_ALL_TESTS
	      mkdir pytbull_t5pcap_based_runs
	      mv test_output_et_free_rules pytbull_t5pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t5pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t5pcap_based_runs/
	      mv test_output_no_rules pytbull_t5pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t5pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_6
	      RUN_ALL_TESTS
	      mkdir pytbull_t6pcap_based_runs
	      mv test_output_et_free_rules pytbull_t6pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t6pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t6pcap_based_runs/
	      mv test_output_no_rules pytbull_t6pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t6pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_7
	      RUN_ALL_TESTS
	      mkdir pytbull_t7pcap_based_runs
	      mv test_output_et_free_rules pytbull_t7pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t7pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t7pcap_based_runs/
	      mv test_output_no_rules pytbull_t7pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t7pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_8
	      RUN_ALL_TESTS
	      mkdir pytbull_t8pcap_based_runs
	      mv test_output_et_free_rules pytbull_t8pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t8pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t8pcap_based_runs/
	      mv test_output_no_rules pytbull_t8pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t8pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_9
	      RUN_ALL_TESTS
	      mkdir pytbull_t9pcap_based_runs
	      mv test_output_et_free_rules pytbull_t9pcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_t9pcap_based_runs/
	      mv test_output_et_pro_rules pytbull_t9pcap_based_runs/
	      mv test_output_no_rules pytbull_t9pcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_t9pcap_based_runs/
#
	      PCAP_FILE=$PCAP_FILE_PytBull_ALL
	      RUN_ALL_TESTS
	      mkdir pytbull_allpcap_based_runs
	      mv test_output_et_free_rules pytbull_allpcap_based_runs/
	      mv test_output_et_free_rules_tweeked pytbull_allpcap_based_runs/
	      mv test_output_et_pro_rules pytbull_allpcap_based_runs/
	      mv test_output_no_rules pytbull_allpcap_based_runs/
	      mv test_output_no_rules_tweeked pytbull_allpcap_based_runs/
	      exit 1
	      ;;
	  p)
	      DASH_P_OPTION_END_OF_STUDY_LOG_BUILDING
	      ;;
	  g)
	      PLOTS_MEMORY_V_WORKLOAD
	      PLOTS_CPU_UTILIZATION_V_WORKLOAD
	      PLOTS_PPS_V_NUMER_OF_CORES
	      ;;
	  s)
	      PCAP_FILE=$OPTARG 
	      RUNTESTS
	      exit 1
	      ;;
	  v)
	      echo $VERSION
	      exit 1
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
	      exit 1
	      ;;
	  ?)
	      SCRIPT_USAGE
	      exit 1
	      ;;
	esac
    done

    fi


#set -v off
#set -x off
#echo "done"
