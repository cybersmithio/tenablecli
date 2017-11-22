# Overview
This is a Python script to provide a command line interface with Tenable's SecurityCenter and Tenable.io products.  You can download Python for Unix, Windows, and Mac at https://www.python.org/


This script requires the following Python libraries:
*The pySecurityCenter project at https://github.com/SteveMcGrath/pySecurityCenter 
*The Tenable.io SDK at https://github.com/tenable/Tenable.io-SDK-for-Python/
*The netaddr library at https://pypi.python.org/pypi/netaddr
*The ipaddr library at https://pypi.python.org/pypi/ipaddr

The last two libraries can be installed by running: **pip install netaddr ipaddr**


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

To launch: **./tenablecli.py agent download csv**


# Report on scan zones that overlap
This is currently only available for SecurityCenter, as Tenable.io does not use scan zones.  Overlapping scan zones do not necssarily mean there is a problem with the configuration.  Some organizations having overlapping network ranges for various reasons.

To launch: **./tenablecli.py scanzone overlaps**

# Launch a quick scan
This is currently only available for SecurityCenter (just because).  This launches a scan with just one plugin enabled (and possibly some dependencies), and scans just one target.

To launch: **./tenablecli.py scan quick** *pluginID repositoryID target targetPort*
