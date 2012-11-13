# -*- coding: utf-8 -*-
"""
Created on Sat Nov 10 23:14:52 2012

@author: - Joshua White
         - whitejs@clarkson.edu
         
"""

from PyIDSBenchFunc import ScriptUsage, PrintVersion, WhatIDSArePresent
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
        opts, args = getopt.getopt(argv, "h?d:t:n:ap:vui", ["help", "directory=", 
                                                          "ids_type=", "number_of_runs=", 
                                                          "pcap_file=", "unittests", "ids_check"])
    except getopt.GetoptError:
        sys.exit(2)
        
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
    
if __name__ == "__main__":
    main(sys.argv[1:])
    