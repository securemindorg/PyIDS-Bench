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
import psutil
import time
import subprocess
import matplotlib
matplotlib.use('Agg')                                           # Sets matplotlib up to not require X11
from matplotlib.mlab import csv2rec                             # easier csv reading
import matplotlib.pyplot as plt                                 # easier calling of matplotlib.pyplot
import matplotlib.dates as mdates                               # neat function for working with date formats
from pylab import *                                             # used for formatting the graphs



def GetDateTime():
    
    ''' This function gets the data and time for logging reasons '''

    InfoTimeNow = datetime.datetime.now().strftime('%m/%d/%G -- %T - <Info> -')
    WarningTimeNow = datetime.datetime.now().strftime('%m/%d/%G -- %T - <Warning> -')
    ErrorTimeNow = datetime.datetime.now().strftime('%m/%d/%G -- %T - <Error> -')

    return InfoTimeNow, WarningTimeNow, ErrorTimeNow
    
def SysLogging(logmessage):
    
    ''' This function is used to log status messages to syslog. For the moment 
    I'm cheating and using Logger the bash utility. I realize this isn't the most
    pythonic way of doing things, however logger is tried and true and something that
    I know how to work with at the moment. Therefore I would rather just get a quick
    solution in place and go from there '''
    
    BashLogger = "logger " + logmessage
    
    logprocess = subprocess.Popen(BashLogger.split(), stdout=subprocess.PIPE)
    output = logprocess.communicate()[0]
    

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
    
    
def ProcessMonitor(ProcessName):

    ''' This function defines the necessary steps to creating a cpu and memory process monitor. 
    Contained within is the necessary code for writing a csv file with new rows every second. In
    addition I'm using the multiprocessing library to spawn everything off. I am not using the
    threading module because it does not take into account the multiple core availablbility of
    most systems. In additon the threading library impliments time slicing which I have a 
    feeling is going to cause a problem when it comes to acuratly monitoring over a large 
    period of time'''

    def ActualProcessMonitor(ProcessName):
        while True:
                output_sys = open("/tmp/sysstats_counter.log", 'a')
        
                for proc in psutil.process_iter():
                        if proc.name == ProcessName:
                                p = proc
        
                p.cmdline
        
                proc_rss, proc_vms =  p.get_memory_info()
                proc_cpu =  p.get_cpu_percent(1)
        
                scol1 = str(proc_rss / 1024)
                scol2 = str(proc_cpu)
        
                now = str(datetime.datetime.now())
        
                output_sys.write(scol1)
                output_sys.write(", ")
                output_sys.write(scol2)
                output_sys.write(", ")
                output_sys.write(now)
                output_sys.write("\n")
        
                output_sys.close( )
        
                time.sleep(1)
    

    APM = multiprocessing.Process(target=ActualProcessMonitor, args=(ProcessName,))
    APM.start()
    

def CreateGraphs():
    
    ''' This function creates graphs as png images and returns an update value'''
    
    input = open(sys_stat_input_filename, 'r')
    output = open(sys_stat_output_tmp_filename, 'w')                                                                                                                            
                                                                                                                                                                           
    filtered = (line for line in input if not line.startswith('-'))
    
    for line in filtered:                                                                                                                                                   
        filtered2 = (line for line in input if not line.startswith('0'))
        for line in filtered2:
            output.write(line) 
     
    input.close()
    output.close()
    
    data = csv2rec(sys_stat_output_tmp_filename, names=['rss', 'cpupercent', 'time'])
    
    rcParams['figure.figsize'] = 20, 5                              # this sets the dimensions of the graph to be made
    rcParams['font.size'] = 8                                       # sets the font sizes on the graph
    
    fig = plt.figure()                                              # This is the actual plot function
    
    plt.plot(data['time'], data['rss'])                             # this sets the fields to be graphed
    
    ax = fig.add_subplot(111)                                       # this sets up the subplots which is basically the layering for axis's
    ax.plot(data['time'], data['rss'])                              # set the fields for the x,y axis labeling
    minutes = mdates.MinuteLocator()                                # find the hour marks out of the data and label them on the plot 
    fmt = mdates.DateFormatter('%D - %H:%M')                        # setup the format for the labeling of the dates/times
    ax.xaxis.set_major_locator(minutes)                             # set the major intervals for ticks on the graph
    ax.xaxis.set_major_formatter(fmt)                               # apply the date/time format
    
    ax.grid()                                                       # turn on the plot grids
    
    plt.ylabel("Average KB/Sec Memory Usage")                       # this sets the y label
    PlotTitle = ProcessName + " Process Memory Usage (Total RSS)"
    plt.title(PlotTitle)                                            # this sets the title
    
    fig.autofmt_xdate(bottom=0.2, rotation=90, ha='left')           # rotate the x axis labels
    
    plt.savefig(mem_output_image_name)
    
    fig2 = plt.figure()                                             # This is the actual plot function
    
    plt.plot(data['time'], data['cpupercent'])                      # this sets the fields to be graphed
    
    ax2 = fig.add_subplot(111)
    ax2.plot(data['time'], data['cpupercent'])
    minutes = mdates.MinuteLocator()                                # find the hour marks out of the data and label them on the plot
    fmt = mdates.DateFormatter('%D - %H:%M')                        # setup the format for the labeling of the dates/times
    ax2.xaxis.set_major_locator(minutes)                            # set the major intervals for ticks on the graph
    ax2.xaxis.set_major_formatter(fmt)                              # apply the date/time format
    
    ax2.grid()
    
    plt.ylabel("Average CPU Usage (Total Per All Cores)")           # this sets the y label
    PlotTitle = ProcessName + " Process CPU Usage"
    plt.title(PlotTitle)                                            # this sets the title
    
    fig2.autofmt_xdate(bottom=0.2, rotation=90, ha='left')          # rotate the x axis labels
    
    plt.savefig(cpu_output_image_name)
    
    os.remove(sys_stat_output_tmp_filename)                         # This removes the tempfile
    
    ''' This still needs added content for graphing the packet performance related items '''

    
def MinMaxMean(ResultsArray):
    
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
    
    
def CreateHTMLPage():
    
    ''' This function creates the output webpage '''
    
    return HTMLUpdate
    
def RunWebServer():
    
    ''' This function runs the python web server '''
    
    return 
    