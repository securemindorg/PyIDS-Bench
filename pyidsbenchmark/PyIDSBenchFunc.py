# -*- coding: utf-8 -*-
"""
Created on Sat Nov 10 23:14:52 2012

@author: - Joshua White
         - whitejs@clarkson.edu
         
"""

from PyIDSBenchGlobals import *
import multiprocessing
import datetime
import os
import netifaces


def GetDateTime():
    
    ''' This function gets the data and time for logging reasons '''

    InfoTimeNow = datetime.datetime.now().strftime('%m/%d/%G -- %T - <Info> -')
    WarningTimeNow = datetime.datetime.now().strftime('%m/%d/%G -- %T - <Warning> -')
    ErrorTimeNow = datetime.datetime.now().strftime('%m/%d/%G -- %T - <Error> -')

    return InfoTimeNow, WarningTimeNow, ErrorTimeNow

def ScriptUsage():

    ''' This function defines the help statements '''


    InfoTimeNow, WarningTimeNow, ErrorTimeNow = GetDateTime()
    NumCPUsAvailable = multiprocessing.cpu_count()    
    NetworkInterfacesAvailable = netifaces.interfaces()
    LinuxVersion = os.uname()
    
    
    print InfoTimeNow, "This is PyIDS Bench version:", VERSION
    print InfoTimeNow, "Number CPUs/Cores avalable:", NumCPUsAvailable
    print InfoTimeNow, "Network inerfaces available:", NetworkInterfacesAvailable  
    print InfoTimeNow, "Linux version:", LinuxVersion
   
    print ''' 
    
    Python Intrusion Detection System Benchmark (PyIDS Bench): 
    
        - Is a system for measuring various performance benchmarks of multiple IDS systems
        
        - Current IDS support = Snort, Suricata

    Usage Options:

        - Do not specify more then one command line option at a time, we're not setup to handle that yet.

        -h / -?                 :   Show this help page
        -d  [directory]         :   Creates the initial directory structure based on the location specified
                                    This is necessary for the utility to run correctly, if the directory structure is not created
                                    If no location is specified /tmp/PyIDSTests is used
        -t  [ids_type]          :   This runs all tests for a specified single IDS.
                                    Currently support keywords are "snort", "suricata".             
        -n  [number_of_runs]    :   If specified along with -t more then one run of each test will be performed.
                                    The output of this will result in a standard deviation being calculated.
        -a                      :   If specified all IDS present are tested using all available ruleset configurations.
                                    You should also specify -n as no less then 4 for test brevity 
        -p  [pcap_file]         :   Specifiy a PCap file for use.
                                    This should be at least 1 GB in size.
                                    We recommend iCTF "International Capture The Flag" competition pcaps as they
                                    are readily available, large and consist of various protocols.
        -i                      :   Check for present IDS's
        -v                      :   Prints Version Information
 
	Example Usage:

	  #  pyidsbench -d /tmp/PyIDSTests -a -t 5 -s /tmp/test.pcap  

    '''

def PrintVersion():
    
    ''' This function prints version information '''

    print     
    print "PyIDS Benchmark Version: ", VERSION    
    print
    
    return 

def WhatIDSArePresent():
    ''' This function checks to see what IDS systems are present 
        currently this includes Snort and Suricata '''
        
    Suricata_Exists = os.path.exists(DEFAULT_SURICATA_PATH)
    Snort_Exists = os.path.exists(DEFAULT_SNORT_PATH)

    print

    if Suricata_Exists == True:
        print "Suricata was found in the default path: ", DEFAULT_SURICATA_PATH
    else:
        print "Suricata was NOT found int he default path: ", DEFAULT_SURICATA_PATH
        
    if Snort_Exists == True:
        print "Snort was found in the default path: ", DEFAULT_SNORT_PATH
    else:
        print "Snort was NOT found in the default path: ", DEFAULT_SNORT_PATH

    print
    
    return 

def MinMaxMean():
    
    ''' This function gets the min max and mean of a series of numbers '''
    
    return Min, Max, Mean
    

def StandardDeviation():
    
    ''' This function calculates the standard deviation of the multiple test runs '''
    
    return StandardDev
    
def RunAllTests():
    
    ''' This runs benchmarks on all IDS's currently supported '''
    
    SuricataTests()
    SnortTests()
    
    return
    
def SuricataTests():
    
    ''' This runs only the suricata benchmarks '''
    
    return
    
def SnortTests():
    
    ''' This runs only the snort benchmarks '''
    
    return
    
def ProcessLogFiles():
    
    ''' This processes all the log files in preperation for reporting '''    
    
    return
    
def CreateGraphs():
    
    ''' This function creates graphs as png images and returns an update value'''
    
    return GraphUpdate
    
def CreateHTMLPage():
    
    ''' This function creates the output webpage '''
    
    return HTMLUpdate
    
def RunWebServer():
    
    ''' This function runs the python web server '''
    
    return 
    