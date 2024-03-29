# -*- coding: utf-8 -*-
"""
Created on Sat Nov 10 23:14:52 2012

@author: - Joshua White
         - whitejs@clarkson.edu
"""

VERSION = "1.0.0"

DEFAULT_SAVE_DIRECTORY = "/tmp/PyIDSBench/"
DEFAULT_IDS_TYPE = "suricata"
DEFAULT_NUMBER_OF_RUNS = 1
DEFAULT_PCAP_FILE = "/tmp/test.pcap"

CURRENT_PCAP_FILE = " "

DEFAULT_SURICATA_PATH = "/usr/local/bin/suricata"
DEFAULT_SNORT_PATH = "/usr/local/bin/snort"
DEFAULT_YUM_PATH = "/etc/yum"
DEFAULT_GCC_PATH = "/usr/lib/gcc"

DEFAULT_ET_FREE_RULES_PATH = " "
DEFAULT_VRT_FREE_RULES_PATH = " "

SURICATA_CURRENT_CONFIG_FILE = "/usr/local/etc/suricata/suricata.yaml"

SURICATA_DEFUALT_NO_RULES_DEFAULT_CONFIG = " "
SURICATA_DEFUALT_OPEN_ET_RULESET_CONFIG = " "
SURICATA_DEFUALT_VRT_FREE_RULESET_CONFIG = " "
SURICATA_OPTOMIZED_NO_RULES_DEFAULT_CONFIG = " "
SURICATA_OPTOMIZED_OPEN_ET_RULESET_CONFIG = " "
SURICATA_OPTOMIZED_VRT_FREE_RULESET_CONFIG = " "

SURICATA_DEFAULT_LOG_DIR = "/usr/local/var/log/suricata/"

SNORT_DEFUALT_NO_RULES_DEFAULT_CONFIG = " "
SNORT_DEFUALT_OPEN_ET_RULESET_CONFIG = " "
SNORT_DEFUALT_VRT_FREE_RULESET_CONFIG = " "
SNORT_OPTOMIZED_NO_RULES_DEFAULT_CONFIG = " "
SNORT_OPTOMIZED_OPEN_ET_RULESET_CONFIG = " "
SNORT_OPTOMIZED_VRT_FREE_RULESET_CONFIG = " "

# These define how suricata is installed using the PyIDS Bench on the system

DEFAULT_SURICATA_GIT_LOCATION = "git clone git://phalanx.openinfosecfoundation.org/oisf.git"
DEFAULT_SURICATA_INSTALLATION_COMMANDS = "cd oisf/ && ./autogen && ./configure --enable-unittests --enable-profiling && make && make install && make install-full"
DEFAULT_SURICATA_MKDIR_LOG_DIR = "mkdir " + SURICATA_DEFAULT_LOG_DIR
DEFAULT_SURICATA_STATS_FILE = "stats.log"
DEFAULT_SURICATA_STATS_OUTPUT_FILE = "suricata_stats_output.csv"

DEFAULT_SNORT_DOWNLOAD_LOCATION = "http://downloads.sourceforge.net/project/snort/snort/snort-2.9.3.1.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fsnort%2F%3Fsource%3Ddirectory&ts=1353445325&use_mirror=heanet"
DEFAULT_SNORT_VERSION = "snort-2.9.3.1.tar.gz"
DEFAULT_DAQ_DOWNLOAD_LOCATION = "http://www.snort.org/downloads/1850"
DEFAULT_SNORT_STATS_LOG_DIR = "/var/log/snort/"
DEFAULT_SNORT_STATS_FILE = "snort.stats"
DEFAULT_SNORT_STATS_OUTPUT_FILE = "snort_stats_output.csv"

# The globals below are not to be modified, they are simply default values that are being initialized

ProcessName = "firefox"
mem_output_image_name = './graphing_tests/mem.png'                      # set the name of the output image
cpu_output_image_name = './graphing_tests/cpu.png'
sys_stat_input_filename = "./graphing_tests/sysstats_counter.log"
sys_stat_output_tmp_filename = "/tmp/sysstats_counter.log_noneg.tmp"
suricata_stats_run_count_name = "run_1_suricata-stats.log"

UNIQUE_RUNS_ID = " "
