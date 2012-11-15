# -*- coding: utf-8 -*-
"""
Created on Sat Nov 10 23:14:52 2012

@author: - Joshua White
         - whitejs@clarkson.edu
         
"""

from PyIDSBenchFunc import ScriptUsage, PrintVersion, WhatIDSArePresent, GetDateTime, CreateGraphs, ProcessMonitor, SysLogging
from PyIDSBenchGlobals import *
import sys
import getopt

# This specifys the default options in the even that they aren't given by user
directory = DEFAULT_SAVE_DIRECTORY
ids_type = DEFAULT_IDS_TYPE
number_of_runs = DEFAULT_NUMBER_OF_RUNS
pcap_file = DEFAULT_PCAP_FILE

def main(argv):

    ''' This is the main function '''
        
    try:
        opts, args = getopt.getopt(argv, "h?d:t:n:ap:vuigPL", ["help", "directory=", 
                                                          "ids_type=", "number_of_runs=", 
                                                          "pcap_file=", "unittests", "ids_check"])
    except getopt.GetoptError:
        sys.exit(2)
       
    if opts > 0:

        for option, argument in opts:
    
            if option in ("-h", "-?", "--help"): 
                ScriptUsage()              
                sys.exit()
    
            elif option in ("-d", "--directory"):
                directory = argument
                DEFAULT_SAVE_DIRECTORY = directory
                print directory
            
            elif option in ("-t", "--ids_type"):
                ids_type = argument
                DEFAULT_IDS_TYPE = ids_type
                print ids_type
            
            elif option in ("-n", "--number_of_runs"):
                number_of_runs = argument
                DEFAULT_NUMBER_OF_RUNS = number_of_runs
                print number_of_runs
                
            elif option == "-a":
                print "run all tests"
            
            elif option in ("-p", "--pcap_file"):
                pcap_file = argument
                DEFAULT_PCAP_FILE = pcap_file
                print pcap_file
                
            elif option == "-v":
                PrintVersion()
            
            elif option in ("-u", "--unittests"):
                print "unit tests"
            
            elif option in ("-i", "--ids_check"):
                WhatIDSArePresent()
            
            elif option in ("-g"):
                ''' this is just for dev use, the goal is to have something 
                to test graphing with without having to gather data every time, this option will
                be removed before final release and as such is not listed in the help screen '''
                CreateGraphs()
                
            elif option in ("-P"):
                ''' this is again another test statement to make sure the process monitoring
                function spawns a child process and works properly, it makes the assumption
                that ProcessName is defined in the Globals file.'''
                ProcessMonitor(ProcessName)
                
            elif option in ("-L"):
                ''' same deal, this is a test statement for the logger function '''
                SysLogging("This is a test and only a test")
#    else:
#        InfoTimeNow, WarningTimeNow, ErrorTimeNow = GetDateTime()
#        print ErrorTimeNow, "You did not specify any command line options:"
#        ScriptUsage()
    
if __name__ == "__main__":
    main(sys.argv[1:])
    
