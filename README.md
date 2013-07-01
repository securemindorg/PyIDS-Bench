# PyIDS-Bench #
PyIDS-Bench (The Python Intrusion Detection Benchmarking Tool)
is a utility to test the performance and detection capabilities
of various IDS' and compare them to one-and-other on specific 
types of hardware. 

PyIDS-Bench is free to use and licensed under the XXXX. A copy of this
license is available at: http://xxxxxxxxxxxx

Up to date versions of this utility are maintained by XXXXXX and 
can be found at XXXXXXX 

## Build Requirements ##
- python
- python-dev

## Library Requirements ##
All libraries can be installed through pip or easy_install


- datetime
- matplotlib
- multiprocessing
- netifaces
- os
- psutil

## Installation Process ##

Installation is straight forward. 

    git clone https://github.com/securemindorg/PyIDS-Bench.git
    cd PyIDS-Bench
    python setup.py install


## Running ##

Currently (11/23/12) we support running tests on Suricata:

`python PyIDSBench.py -n 2 -p "klpd.pcap" -t suricata`

which runs suricata twice on the klpd.pcap... This obviously only works if 
you have a config file for suricata allready setup and you have the klpd.pcap.
