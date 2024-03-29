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
#
# It should be noted that since we're only measureing the process ID specified in pidstat
# we don't need to worry about results being skewed by running this script.
#
# Version: v7
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
# 
# whitejs@clarkson.edu

#################
### Settings  ###
#################

     # Define your pcap file location here:
     PCAP_FILE="/mnt/ictf2010.pcap2"
     SURICATA_CONFIG="/etc/suricata/suricata.yaml"
     SNORT_CONFIG="/etc/snort/snort.conf"
     SAMPLING_TIME=120 #in seconds
     MAX_LOG_DURATION=4000 #in seconds
     LOG_INTERVAL=1 #in seconds
     OUTPUT_DIRECTORY="test_output"
     IDS_COMPARISON_TESTING_LOG="run.log"

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

####################################################################
### Startup / Test For Root / Test For Existing Output Directory ###
####################################################################

# make sure we're running as root
if [[ $EUID -ne 0 ]]; then

  echo "This script will only work if you are root"
  exit 1

else

  # Test If Output Dir Exist 
  if [ -d $OUTPUT_DIRECTORY ];then
    
    echo "Dirctories Exist, before continuing please move the data and rm the directories before we overwrite it."
    exit 1

  else

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
	echo "Time,PID,%usr,%system,%guest,%CPU,CPU,minflt/s,majflt/s,VSZ (KB),RSS (KB),%MEM,Command" > process-suricata-stats.csv

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
	      paste temp11.file temp9.file | sed 's/\t/,/g' >> process-suricata-stats.csv

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

		    echo "time,packet count,PPS" > suricata-stats.csv
		    paste temp4.file temp6.file | sed 's/\t/,/g' >> suricata-stats.csv

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
	echo "Time,PID,%usr,%system,%guest,%CPU,CPU,minflt/s,majflt/s,VSZ (KB),RSS (KB),%MEM,Command" > process-snort-stats.csv

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
	      paste temp11.file temp9.file | sed 's/\t/,/g' >> process-snort-stats.csv

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
		    echo "time,k-pps,pps" > snort-stats.csv

		    # this line takes the timestamps and the packet count and calculates a third column PPS and puts them into the csv
		    paste temp3.file temp2.file | sed 's/\t/,/g' | uniq | awk 'BEGIN {FS=OFS=","}{$3=$2*1000}1' >> snort-stats.csv

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
                 SURICATA_PROC_START_TIME=$(head -n 2 process-suricata-stats.csv | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SURICATA_PROC_END_TIME=$(tail -n 1 process-suricata-stats.csv | cut -d, -f 1)

                 # Get snort start and stop process times
                 SNORT_PROC_START_TIME=$(head -n 2 process-snort-stats.csv | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SNORT_PROC_END_TIME=$(tail -n 1 process-snort-stats.csv | cut -d, -f 1)

                 # Calculate Suricata total Process run time
                 let SURICATA_TOT_PROC_RUN_TIME=$(date +%s -d $SURICATA_PROC_END_TIME)-$(date +%s -d $SURICATA_PROC_START_TIME)

                 # Calculate Snort total Process run time
                 let SNORT_TOT_PROC_RUN_TIME=$(date +%s -d $SNORT_PROC_END_TIME)-$(date +%s -d $SNORT_PROC_START_TIME)

           #######################################################################
           ### Calculate the total actual run time for both snort and suricata ###
           #######################################################################

                 # Get suricata start and stop process times
                 SURICATA_STATS_START_TIME=$(head -n 2 suricata-stats.csv | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SURICATA_STATS_END_TIME=$(tail -n 1 suricata-stats.csv | cut -d, -f 1)

                 # Get snort start and stop process times
                 SNORT_STATS_START_TIME=$(head -n 2 snort-stats.csv | sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1)
                 SNORT_STATS_END_TIME=$(tail -n 1 snort-stats.csv | cut -d, -f 1)

                 # Calculate Suricata total Process run time
                 let SURICATA_TOT_STATS_RUN_TIME=$(date +%s -d $SURICATA_STATS_END_TIME)-$(date +%s -d $SURICATA_STATS_START_TIME)

                 # Calculate Snort total Process run time
                 let SNORT_TOT_STATS_RUN_TIME=$(date +%s -d $SNORT_STATS_END_TIME)-$(date +%s -d $SNORT_STATS_START_TIME)

           ################################################################################
           ### Calculate the CPU stats (MIN, MAX, AVG) Used for both snort and suricata ###
           ################################################################################

                SURICATA_CPU_NUM_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-suricata-stats.csv | cut -d, -f 7 | awk 'BEGIN {FS=","}
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
                  }')


                SNORT_CPU_NUM_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-snort-stats.csv | cut -d, -f 7 | awk 'BEGIN {FS=","}
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
                  }')

          ########################################################################################
          ### Calculate the CPU % Usage stats (MIN, MAX, AVG) Used for both snort and suricata ###
          ########################################################################################

                SURICATA_CPU_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-suricata-stats.csv | cut -d, -f 6 | awk 'BEGIN {FS=","}
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
                  }')


                SNORT_CPU_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-snort-stats.csv | cut -d, -f 6 | awk 'BEGIN {FS=","}
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
                  }')

          #####################################################################################################
          ### Calculate the RSS (MEMORY) Usage stats in KB (MIN, MAX, AVG) Used for both snort and suricata ###
          #####################################################################################################

                SURICATA_RSS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-suricata-stats.csv | cut -d, -f 11 | awk 'BEGIN {FS=","}
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
                  }')


                SNORT_RSS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-snort-stats.csv | cut -d, -f 11 | awk 'BEGIN {FS=","}
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
                  }')

          ########################################################################################
          ### Calculate the MEM % Usage stats (MIN, MAX, AVG) Used for both snort and suricata ###
          ########################################################################################

                SURICATA_MEM_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-suricata-stats.csv | cut -d, -f 12 | awk 'BEGIN {FS=","}
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
                  }')


                SNORT_MEM_PERCENT_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' process-snort-stats.csv | cut -d, -f 12 | awk 'BEGIN {FS=","}
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
                  }')

          ########################################################################
          ### Calculate PPS (MIN, MAX, AVG, TOTAL) for both snort and suricata ###
          ########################################################################

                SURICATA_PPS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' suricata-stats.csv | cut -d, -f 3 | awk 'BEGIN {FS=","}
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
                    print min",",max",",total/count",",total;
                  }')


                SNORT_PPS_STATS=$(sed '1d;/^[Time]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' snort-stats.csv | cut -d, -f 3 | awk 'BEGIN {FS=","}
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
                    print min",",max",",total/count",",total;
                  }')

     # print the final entries into the log file
     echo "suricata,$PCAP_FILE,$SURICATA_TOT_PROC_RUN_TIME,$SURICATA_TOT_STATS_RUN_TIME,$SURICATA_CPU_NUM_STATS,$SURICATA_CPU_PERCENT_STATS,$SURICATA_RSS_STATS,$SURICATA_MEM_PERCENT_STATS,$SURICATA_PPS_STATS" | sed 's/ //g' >> $IDS_COMPARISON_TESTING_LOG
     echo "snort,$PCAP_FILE,$SNORT_TOT_PROC_RUN_TIME,$SNORT_TOT_STATS_RUN_TIME,$SNORT_CPU_NUM_STATS,$SNORT_CPU_PERCENT_STATS,$SNORT_RSS_STATS,$SNORT_MEM_PERCENT_STATS,$SNORT_PPS_STATS" | sed 's/ //g'>> $IDS_COMPARISON_TESTING_LOG

     ############################################
     ### Move Everything to it's proper place ###
     ############################################

     mv *.csv $OUTPUT_DIRECTORY
     mv $IDS_COMPARISON_TESTING_LOG $OUTPUT_DIRECTORY

  fi

fi

#################################
### End Script With Good Exit ###
#################################

exit 1