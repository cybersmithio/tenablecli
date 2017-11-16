# Overview
This is a Python script to provide a command line interface with Tenable's SecurityCenter and Tenable.io products.  You can download Python for Unix, Windows, and Mac at https://www.python.org/


This script requires both the pySecurityCenter project at https://github.com/SteveMcGrath/pySecurityCenter and the Tenable.io SDK at https://github.com/tenable/Tenable.io-SDK-for-Python/

# Using With Security Center On Unix/Linux/BSD
To instruct tenablecli to interact with a SecurityCenter installation, set the following environment variables

SCHOST=192.168.1.1; export SCHOST

SCUSERNAME=jamessmith;export SCUSERNAME

SCPASSWORD=***********;export SCPASSWORD

# Using With Tenable.io On Unix/Linux/BSD
To instruct tenablecli to interact with Tenable.io, set the following environment variables

TIOHOST=cloud.tenable.com; export TIOHOST

TIOACCESSKEY=jamessmith;export TIOACCESSKEY

TIOSECRETKEY=***********;export TIOSECRETKEY

# Using With Tenable.io On Windows
To instruct tenablecli to interact with Tenable.io, set the following environment variables

set TIOHOST=cloud.tenable.com

set TIOACCESSKEY=jamessmith

set TIOSECRETKEY=***********

# Launching Scans
The syntax to launch scans differs between SecurityCenter and Tenable.io, since Tenable.io has introduced the concept of folders.


To launch a scan in SecurityCenter the syntax is: ./tenablecli.py scan launch scanname

For example: ./tenablecli.py scan launch "Basic network scan of server VLAN"


To launch a scan in Tenable.io the syntax is: ./tenablecli.py scan launch foldername scanname

For example: ./tenablecli.py scan launch "Server Scans" "Basic network scan of server VLAN"

# Downloading a CSV of all agents
This is currently only available for Tenable.io.  Running this will create an agents.csv file in the current directory.

To launch: ./tenablecli.py agent download csv
