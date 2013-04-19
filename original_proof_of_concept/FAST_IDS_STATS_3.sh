#!/bin/bash
#
# In this version I've thrown in some simple math to automatically calculate the PPS 
# based on the suricata output file and gotten rid of the duplicate lines that seem to 
# ocationally occur. BTW: I'm submitting a bug to the OISF about that. 
#
# See Lines: (added 36-59 to help with calculating PPS in suricata) (added 78-93 to convert time stamps from snort log)
# 
# whitejs@clarkson.edu

# Define your pcap file location here:
PCAP_FILE="/mnt/ictf2010.pcap2"
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
SNORT_CONFIG="/etc/snort/snort.conf"
SAMPLING_TIME=120 #in seconds

# Clean Everything
echo " " > /var/log/suricata/stats.log && echo " " > /var/log/snort/snort.stats

# get ps stats loop (suricata)
touch out.2 && for (( i=1;i<=$SAMPLING_TIME;i+=1 )) ; do ps eufp $(pidof suricata) >> out.2; sleep 1; done & 

# start suricata
suricata -c $SURICATA_CONFIG -r $PCAP_FILE

# turn out.2 (the ps stats file) into a csv
touch out.3 && cat out.2 | sed '1d;/^[%CPU]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1,2,3,4,5,6,7,8,9,10,11 >> out.3

# create the final suricata process stats file
touch process-suricata-stats.csv && echo "User,PID,%CPU,%MEM,VSZ,RSS,TTY,STAT,START,PID Time,Command" >> process-suricata-stats.csv
cat out.3 | sed 's/\t/,/g' >> process-suricata-stats.csv

# get and process suricata's own stats file
cat /var/log/suricata/stats.log | grep "Date" | cut -c 21-28 > temp1.file
cat /var/log/suricata/stats.log | grep "decoder.ipv4" | cut -c 57-100 >> temp2.file

paste temp1.file temp2.file | sed 's/\t/,/g' >> temp3.file

touch temp4.file
uniq temp3.file > temp4.file  

echo 0 > temp5.file
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

echo "time,packet count,PPS" > suricata-stats.csv
paste temp4.file temp6.file | sed 's/\t/,/g' >> suricata-stats.csv

# clean up and get ready to start over with snort
rm -f out.* temp*.file

# get ps stats loop (snort)
touch out.2 && for (( i=1;i<=$SAMPLING_TIME;i+=1 )) ; do ps eufp $(pidof snort) >> out.2; sleep 1; done &

# start snort
snort -c $SNORT_CONFIG -r $PCAP_FILE

# turn out.2 (the ps stats file) into a csv
touch out.3 && cat out.2 | sed '1d;/^[%CPU]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' | cut -d, -f 1,2,3,4,5,6,7,8,9,10,11 >> out.3

# create the final snort process stats file
touch process-snort-stats.csv && echo "User,PID,%CPU,%MEM,VSZ,RSS,TTY,STAT,START,PID Time,Command" >> process-snort-stats.csv
cat out.3 | sed 's/\t/,/g' >> process-snort-stats.csv

# get and process snort's own stats file
cut -d, -f 1 /var/log/snort/snort.stats | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' > temp1.file
cut -d, -f 5 /var/log/snort/snort.stats | sed '1d;/^[#]/d;/^$/d;s/^[ ]*//;s/[ ]\+/,/g' > temp2.file

INPUT="temp1.file"

#  this converts the unix timestamp to human readable and selects only the hh:mm:ss portion of it for printout
while read line
  do
    date -d @$line | cut -d" " -f 5 >> temp3.file
  done < "$INPUT" # this sets up the final csv and gives it headers echo "time, kilo-pps, pps" > snort-stats.csv

# this line takes the timestamps and the packet count and calculates a third column PPS and puts them into the csv
paste temp3.file temp2.file | sed 's/\t/,/g' | uniq | awk 'BEGIN {FS=OFS=","}{$3=$2*1000}1' >> snort-stats.csv

# clean up and get read to start over
 rm -f out.* temp*.file