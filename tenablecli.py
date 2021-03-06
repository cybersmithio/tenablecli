#!/usr/bin/python
#
# This script provides command line functionality for managing 
# Tenable SecurityCenter or Tenable.io.
#
#
# Version 1.0 - Initial release
# Version 1.0.1 - Improved error handling.  Thanks to Julien for testing!
#
# Roadmap
#   
# Sample usage with SecurityCenter:
#
# SCHOST=192.168.1.1; export SCHOST
# SCUSERNAME=jamessmith;export SCUSERNAME
# SCPASSWORD=***********;export SCPASSWORD
# ./tenablecli.py scan launch "Basic network scan of server VLAN"
#
#
# TIOHOST=cloud.tenable.com; export TIOHOST
# TIOACCESSKEY=jamessmith;export TIOACCESSKEY
# TIOSECRETKEY=***********;export TIOSECRETKEY
# ./tenablecli.py scan launch "Server Scans" "Basic network scan of server VLAN"
#

import codecs
import sys
import os
import re
import string
import json
import csv
from datetime import datetime,date, time
import time
import requests
from securitycenter import SecurityCenter5
from tenable_io.api.models import Folder
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from tenable_io.api.models import AssetList, AssetInfo, VulnerabilityList, VulnerabilityOutputList
from requests import Request, Session

#To send emails
import smtplib
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

#To check scan zones for overlaps
import netaddr
import ipaddr
		
		
################################################################
# Description: Stops all scans in Tenable.io
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#
################################################################
def StopAllTioScans(tioconn):
	#First upload the XML file, then tell SC to import it.
	DEBUG=True
	if DEBUG:
		print "Stopping all scans in Tenable.io"

	#Sstop all the scans
	tioconn.scan_helper.stop_all

	return(True)

################################################################
# Description: Reports on any overlaps in scan zones
################################################################
# Input:
#        scconn    = The connection handle to SecurityCenter
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#
################################################################
def CheckForScanZoneOverlaps(scconn):
	DEBUG=False
	if DEBUG:
		print "Checking for overlaps in any scan zones"
		print "This are not necessarily a problem depending on your environment"


	resp=scconn.get('zone?fields=name%2Cscanners%2CtotalScanners%2CactiveScanners%2CtotalScanners%2CmodifiedTime%2CcanUse%2CcanManage')

	if DEBUG:
		print resp
		print resp.text

	scanzoneranges=[]
	#Iterate through all the scan zones and download the IP ranges
	for i in resp.json()['response']:
		resp=scconn.get('zone/'+str(i['id'])+'?fields=name%2Cdescription%2CipList%2CcreatedTime%2Cranges%2Cscanners%2Cname%2Cscanners%2CtotalScanners%2CactiveScanners%2CtotalScanners%2CmodifiedTime%2CcanUse%2CcanManage')
		iplist=resp.json()['response']['ipList'].split(',')
		for j in iplist:
			if DEBUG:
				print "IP Range in scan zone",j
			#Check if the IP address is an IP range (instead of a single IP or CIDR)
			hyphen=string.find(j,"-")
			if( hyphen >= 0 ):
				#If the IP address is a range, convert it to CIDR notation
				if DEBUG:
					print "CIDRs",netaddr.iprange_to_cidrs(j[0:hyphen],j[hyphen+1:])

				for k in netaddr.iprange_to_cidrs(j[0:hyphen],j[hyphen+1:]):
					scanzoneranges.append([k,i])
			else:
				scanzoneranges.append([j,i])
	#Examine all the network ranges for overlaps
	#Go through all the ranges, comparing each one to all the other ranges, 
	for i in range(0,len(scanzoneranges)):
		n1=ipaddr.IPNetwork(scanzoneranges[i][0])
		for j in range(i+1,len(scanzoneranges)):
			n2=ipaddr.IPNetwork(scanzoneranges[j][0])
			if n1.overlaps(n2):
				print n1,"in scan zone \""+str(scanzoneranges[i][1]['name'])+"\" overlaps with",n2,"in scan zone \""+str(scanzoneranges[j][1]['name'])+"\""

	return(True)

################################################################
# Description: Retrieve plugin information from SecurityCenter
################################################################
# Input:
#        scconn    = The connection handle to SecurityCenter
#	 pluginid = The plugin ID to run
#
################################################################
# Output:
#        True = JSON structure with plugin information
#        False = Did not successfully complete the operation
################################################################
# To do:
#
################################################################
def GetSCPluginInformation(scconn,pluginid):
	DEBUG=False
	if DEBUG:
		print "Gathering plugin information about plugin ID",pluginid

	url='plugin?filterField=id&op=eq&value='+str(pluginid)+'&endOffset=50&sortDirection=ASC&sortField=name&fields=name%2Cdescription%2Cfamily%2Ctype%2CmodifiedTime'
	if DEBUG:
		print "URL: ",url
	resp=scconn.get(url)

	if DEBUG:
		print "Received response"
		print resp
		print resp.text
	respdata=json.loads(resp.text)
	if respdata['error_code'] == 0:
		plugininfo=respdata['response']
		if DEBUG:
			print "\n\nResponse error code/error message",respdata['error_code'],"/",respdata['error_msg']
			print "\n\nPlugin Info",plugininfo
		return(plugininfo[0])
	return(False)


################################################################
# Description: Launch a scan against one target for one plugin
################################################################
# Input:
#        scconn    = The connection handle to SecurityCenter
#        scantarget   = The target of the scan
#	 scanpluginid = The plugin ID to run
#	 repositoryid = The ID of the repository where the data should be imported
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#
################################################################
def LaunchRemediationScan(scconn,scanpluginid,repositoryid,scantarget,scanport):
	DEBUG=False
	if DEBUG:
		print "Launching remediation scan on",scantarget,"with plugin ID",scanpluginid

	plugininfo=GetSCPluginInformation(scconn,scanpluginid)
	if plugininfo == False:
		if DEBUG:
			print "Problem getting plugin information"
		return(False)
	if DEBUG:
		print "Plugin family info:",plugininfo
		print "Plugin family ID:",plugininfo['family']['id']
		print "Plugin family name:",plugininfo['family']['name']
		print "Plugin family type:",plugininfo['family']['type']

	postdata='{"name":"","description":"","context":"scan","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"policyTemplate":{"id":1},"auditFiles":[],"preferences":{"portscan_range":"'+str(scanport)+'","tcp_scanner":"no","syn_scanner":"yes","udp_scanner":"no","syn_firewall_detection":"Automatic (normal)"},"families":[{"id":"'+str(plugininfo['family']['id'])+'","name":"'+str(plugininfo['family']['name'])+'","type":"'+str(plugininfo['family']['type'])+'","plugins":[{"id":"'+str(scanpluginid)+'"}]},{"id":"41","plugins":[{"id":"19506"}]}]}'
	if DEBUG:
		print "Post data:",postdata
	resp=scconn.post('policy',data=postdata)

	if DEBUG:
		print resp
		print resp.text
	respdata=json.loads(resp.text)
	if respdata['error_code'] != 0:
		if DEBUG:
			print "Problem creating policy"
		return(False)
	policyid=respdata['response']['id']
	if DEBUG:
		print "\n\nResponse error code/error message",respdata['error_code'],"/",respdata['error_msg']
		print "\n\nPolicy ID",policyid

	postdata='{"name":"Quick scan of '+str(scantarget)+' for plugin ID '+str(scanpluginid)+'","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"repository":{"id":"'+str(repositoryid)+'"},"schedule":{"start":"TZID=America/New_York:20171120T160400","repeatRule":"FREQ=NOW;INTERVAL=1","type":"now"},"dhcpTracking":"true","emailOnLaunch":"false","emailOnFinish":"false","reports":[],"type":"policy","policy":{"id":"'+str(policyid)+'"},"pluginID":"'+str(scanpluginid)+'","zone":{"id":-1},"timeoutAction":"rollover","rolloverType":"template","scanningVirtualHosts":"false","classifyMitigatedAge":0,"assets":[],"ipList":"'+str(scantarget)+'","credentials":[],"maxScanTime":"unlimited"}'

	if DEBUG:
		print "Post data:",postdata
	resp=scconn.post('scan',data=postdata)

	if DEBUG:
		print resp
		print resp.text
	respdata=json.loads(resp.text)
	policyid=respdata['response']['id']
	if DEBUG:
		print "\n\nResponse error code/error message",respdata['error_code'],"/",respdata['error_msg']
	if respdata['error_code'] != 0:
		return(False)
	
	return(True)


################################################################
# Description: Find all the scans using a particular policy
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        policyname   = The name of the policy to search the scan
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#
################################################################
def FindTioScansByPolicy(tioconn,policyname):
	DEBUG=False
	if DEBUG:
		print "Finding scans using policy",policyname

	#Set the scan ID and folder ID to blank to start

	#Get a list of all the scans
	resp=tioconn.get("scans")
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata,"\n\n"

	#Find the ID of the folder
	for i in respdata['scans']:
		if DEBUG:
			print "Scan ID:",i['id']

		#Find the policy name of the scan
		resp2=tioconn.get("scans/"+str(i['id']))
		respdata2=json.loads(resp2.text)

		if DEBUG:
			print "Response",respdata2,"\n\n"
			print "Policy name",respdata2['info']['policy']
		if respdata2['info']['policy'] == policyname:
			print "Scan \""+respdata2['info']['name']+"\" uses this policy"

	return(True)

		
################################################################
# Description: Download a list of agents in CSV format
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        filename   = The filename of the CSV file to create
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#
################################################################
def AgentDownloadCSV(tioconn,filename):
	DEBUG=False
	if DEBUG:
		print "Finding all agents and creating CSV",policyname

	#Get a list of all the scans
	resp=tioconn.get("workbenches/assets")
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata,"\n\n"

	with open(filename,"w") as csvfile:
		fieldnames=['id','has_agent','last_seen','operating_system','fqdn','ipv4','ipv6','netbios_name']	
		writer=csv.DictWriter(csvfile,fieldnames=fieldnames)
		writer.writeheader()
		DEBUG=True
		for i in respdata['assets']:
			if i['has_agent'] == True:
				rowdict={'id':i['id'], 'has_agent': i['has_agent'], 'last_seen': i['last_seen'],'operating_system': i['operating_system'], 'fqdn': i['fqdn'], 'ipv4': i['ipv4'], 'ipv6': i['ipv6'], 'netbios_name': i['netbios_name']}
				writer.writerow(rowdict)
	csvfile.close()

	return(True)

		

################################################################
# Description: Submit scan for ASV review
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        scanuuid   = The name of the scan to launch
#
################################################################
# Output:
################################################################
# To do:
#
################################################################
def submitForPCIASVScanUUID(tioconn,scanuuid):
	DEBUG=False
	DEBUG=True
	if DEBUG:
		print "Submitting scan uuid",scanuuid,"for PCI ASV submission"

	resp=tioconn.post("pci-asv/scans/"+str(scanuuid)+"/submit",{})
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata,"\n\n"

	return(True)



################################################################
# Description: Email a PCI ASV Attestation
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        uuid   = The UUID of the Attestation to email
#        recepients = The email recepients
#
################################################################
# Output:
#	 "" = No UUID
#	 UUID is returned
################################################################
# To do:
#
################################################################
def emailPCIASVAttestation(tioconn,uuid,recepients):
	DEBUG=False
	DEBUG=True

	requesturl="pci-asv/attestations/"+str(uuid)+"/reports/certificate"
	
	if DEBUG:
		print "Emailing PCI ASV Attestation",uuid,"to",recepients
		print "request URL :",requesturl

	resp=tioconn.post(requesturl,{})
	if DEBUG:
		print "Raw response text:",resp.text
	respdata=json.loads(resp.text)

	downloadid=""
	try:
		downloadid=respdata['id']
	except:
		print "Unable to start download"
		return(False)

	statusurl="pci-asv/attestations/"+str(uuid)+"/reports/"+downloadid+"/status"
	downloadurl="pci-asv/attestations/"+str(uuid)+"/reports/"+downloadid
	if DEBUG:
		print "Waiting for download ID",downloadid
		print "status URL  :",statusurl
		print "download URL:", downloadurl

	downloadstatus=""
	while( downloadstatus != "ready" ):
		resp=tioconn.get(statusurl)
		if DEBUG:
			print "status URL: ",statusurl
		respdata=json.loads(resp.text)
		downloadstatus=respdata['status']
		if DEBUG:
			print "Current download status",downloadstatus
			print "Raw response",resp.text
		time.sleep(2)

	if DEBUG:
		print "Download status changed to ready"
		print "download URL:", downloadurl

	resp=tioconn.get(downloadurl)
	#if DEBUG:
	#	print "Raw response text:",resp.text
	with open('output.pdf','w') as fp:
		for chunk in resp.text:
			fp.write(chunk.encode('utf-8'))
	fp.close()
	#fp=open("output.pdf","wb")
	#fp.write(resp.text.encode('utf-8').strip())
	#fp.close()

	return(True)

################################################################
# Description: Email a PCI ASV Attestation
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        uuid   = The UUID of the Attestation to email
#        recepients = The email recepients
#
################################################################
# Output:
#	 "" = No UUID
#	 UUID is returned
################################################################
# To do:
#
################################################################
def emailPCIASVAttestation2(tioconn,uuid,recepients,sender,company,mailrelay):
	DEBUG=False
	DEBUG=True
	if DEBUG:
		print "Emailing PCI ASV Attestation",uuid,"to",recepients

	resp=tioconn.get("pci-asv/attestations/"+str(uuid)+"/reports/certificate",{})
	if DEBUG:
		print "URL: pci-asv/attestations/"+str(uuid)+"/reports/certificate"

	fp=open("output.pdf","wb")
	fp.write(resp.content)
	fp.close()
	
	#Create the email message
	msg = MIMEMultipart()
	msg['Subject'] = 'PCI ASV Attestation for '+str(company)
	msg['From'] = sender
	msg['To'] = recepients
	msg.preamble = "Attached is the PCI ASV Attestation for "+str(company)
	msg.attach(MIMEText("Attached is the PCI ASV Attestation for "+str(company)))
	pdf=MIMEApplication(resp.content,_subtype="pdf")
	pdf.add_header('content-disposition', 'attachment', filename = "attestation.pdf")
	msg.attach(pdf)

	s = smtplib.SMTP(mailrelay)
	s.sendmail(sender, recepients, msg.as_string())
	s.quit()
	

	return(True)


################################################################
# Description: Email a PCI ASV Attestation
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        uuid   = The UUID of the Attestation to email
#        recepients = The email recepients
#
################################################################
# Output:
#	 "" = No UUID
#	 UUID is returned
################################################################
# To do:
#
################################################################
def emailPCIASVAttestation3(tiohost,tioaccesskey,tiosecretkey,uuid,recepients):
	#Need to mimick this:
	#curl -s -H "X-ApiKeys: accessKey=$TIOACCESSKEY; secretKey=$TIOSECRETKEY" https://cloud.tenable.com/pci-asv/attestations/307feb82-90ce-40db-940a-0cc9e73e55f8/reports/certificate >attestation.pdf
	DEBUG=False
	DEBUG=True

	downloadurl="https://"+tiohost+"/pci-asv/attestations/"+str(uuid)+"/reports/certificate"
	xapikey="X-ApiKeys: accessKey="+tioaccesskey+"; secretKey="+tiosecretkey
	headers={"X-ApiKeys": "accessKey="+tioaccesskey+"; secretKey="+tiosecretkey}
	if DEBUG:
		print "download URL:", downloadurl
		print "API key:",xapikey
		print "Headers:",headers

	req=requests.get(downloadurl,headers=headers)
	print "headers",req.headers

	print "Encoding:",req.encoding
	#req.encoding="utf-8"
	req.encoding="ISO-8859-1"
	print "Encoding:",req.encoding
	
	fp=open("output.pdf","wb")
	fp.write(req.content)
	fp.close()
	return(True)

################################################################
# Description: Returns a scan's Tenable UUID
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        scanid   = The name of the scan to launch
#
################################################################
# Output:
#	 "" = No UUID
#	 UUID is returned
################################################################
# To do:
#
################################################################
def getLatestPCIASVAttestationUUID(tioconn):
	DEBUG=False
	DEBUG=True
	if DEBUG:
		print "Retrieving latest PCI ASV attestation UUID"

	resp=tioconn.get("pci-asv/attestations")
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata['attestations'],"\n\n"

	latesttime=datetime(1970,1,1)
	uuid=""
	for i in respdata['attestations']:
		if DEBUG:
			print ">>>",i
		x=datetime.strptime(i['updated_at'],"%Y-%m-%dT%H:%M:%S.%fZ")
		if x > latesttime:
			if DEBUG:
				print "Found attestation with more recent time",x
		
			if i['status'] == "passed":
				if DEBUG:
					print "And scan also passed ASV"
				latesttime=x
				uuid=i['uuid']
		if DEBUG:
			print "\n\nLatest Time:",x,"\n\n"
			print "The latest UUID is",uuid

	if DEBUG:
		print "The latest UUID is",uuid

	return(uuid)


################################################################
# Description: Returns a scan's Tenable UUID
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        scanid   = The name of the scan to launch
#
################################################################
# Output:
#	 "" = No UUID
#	 UUID is returned
################################################################
# To do:
#
################################################################
def getScanUUID(tioconn,scanid):
	DEBUG=True
	DEBUG=False
	if DEBUG:
		print "Checking scan ID",scanid,"to see if it is ready for PCI ASV submission"

	resp=tioconn.get("scans/"+str(scanid))
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata,"\n\n"

	return(respdata['info']['uuid'])


################################################################
# Description: Checks if a scan is a PCI ASV scan and if
#              it has passed and is ready for ASV submission.
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        scanid   = The name of the scan to launch
#
################################################################
# Output:
#        True = Scan is ready for submission
#        False = Scan is not ready for submission
################################################################
# To do:
#
################################################################
def checkIfPCIASVClean(tioconn,scanid):
	DEBUG=True
	DEBUG=False
	if DEBUG:
		print "Checking scan ID",scanid,"to see if it is ready for PCI ASV submission"

	try:
		resp=tioconn.get("scans/"+str(scanid))
	except:
		print "Error getting scan information.  Assuming scan is not ready for ASV submission"
		return(False)
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata,"\n\n"
	#If the pci-can-upload flag is not true, then this is not considered a clean ASV scan
	if not respdata['info']['pci-can-upload']:
		return(False)

	
	for i in respdata['vulnerabilities']:
		if DEBUG:
			print i['plugin_id']
		if i['plugin_id'] == 33930:
			if DEBUG:
				print "Found a PCI pass"
			return(True)
		if i['plugin_id'] == 33929:
			if DEBUG:
				print "Found a PCI fail"
			return(False)

	#When in doubt, fail it
	return(False)

		
		
################################################################
# Description: Launches a scan in Tenable.io by folder and name
################################################################
# Input:
#        tioconn    = The connection handle to Tenable.io
#        scanfolder = The folder of the scan to launch
#        scanname   = The name of the scan to launch
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#
################################################################
def LaunchTioScan(tioconn,scanfolder,scanname):
	DEBUG=True
	if DEBUG:
		print "Launching scan",scanname,"in folder",scanfolder

	#Set the scan ID and folder ID to blank to start
	scanid=""
	scanfolderid=""

	#List all the information about the folders and scan names
	resp=tioconn.get("scans")
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata,"\n\n"

	#Find the ID of the folder
	for i in respdata['folders']:
		if DEBUG:
			print "Folder info:",i
		if i['name'] == scanfolder:
			if DEBUG:
				print "Found scan folder ID:",i['id']
			scanfolderid=i['id']
	if scanfolderid == "":
		if DEBUG:
			print "Unable to find scan folder"
		return(False)

	#Find the ID of the scan
	resp=tioconn.get("scans?folder_id"+str(scanfolderid))
	respdata=json.loads(resp.text)

	if DEBUG:
		print "Response",respdata,"\n\n"

	#Find the ID of the folder
	for i in respdata['scans']:
		if DEBUG:
			print "Scan info:",i
		if i['name'] == scanname:
			if DEBUG:
				print "Found scan ID:",i['id']
			scanid=i['id']
	if scanid == "":
		if DEBUG:
			print "Unable to find scan"
		return(False)
	
	if DEBUG:
		print "\n\n\nLaunch scan\n\n\n"
	#Now launch the scan
	scan=tioconn.scan_helper.id(scanid)
	scan.launch()
	
	#resp=tioconn.post("scans/"+str(scanid)+"/launch")
	#resp=tioconn.post("scans/1212/launch")
	#respdata=json.loads(resp.text)

	return(True)

		

################################################################
# Description: Launches a scan by name
################################################################
# Input:
#        scsm = the SecurityCenter Security Manager session object
#        scan = The name of the scan to launch
#
################################################################
# Output:
#        True = Successfully completed operation
#        False = Did not successfully complete the operation
################################################################
# To do:
#        Put the scan name in the scan list filter
#
################################################################
def LaunchScan(scsm,scan):
	#First upload the XML file, then tell SC to import it.
	DEBUG=False
	if DEBUG:
		print "Launching scan",scan

	resp=scsm.get('scan?filter=usable&fields=canUse%2CcanManage%2Cowner%2Cgroups%2CownerGroup%2Cstatus%2Cname%2CcreatedTime%2Cschedule%2Cpolicy%2Cplugin%2Ctype')

	if DEBUG:
		print resp
		print resp.text
	respdata=json.loads(resp.text)
	scanlist=respdata['response']['usable']
	if DEBUG:
		print "\n\nResponse error code/error message",respdata['error_code'],"/",respdata['error_msg']
		print "\n\nScan list",scanlist

	scanid=0
	for i in scanlist:
		if DEBUG:
			print "Scan:"
			print "id:",i['id']
			print "name:",i['name']
			print "\n"
		if i['name'] == scan:
			scanid=int(i['id'])
			if DEBUG:
				print "Found scan! ID is:",i['id']
			

	if scanid != 0:
		if DEBUG:
			print "Scan ID is:",str(scanid)
		resp=scsm.post('scan/'+str(scanid)+'/launch')
		return(True)
	else:
		print "Scan not found"

	return(False)

def DisplayHelp():
	print "Options"
	print "  scan launch"
	print "  scan stop"
	print "  scan stop-all"
	print "  scan quick [plugin ID] [repository ID] [target] [target port]"
	print "  scan pci-submit"
	print "  scan pci-submit when-clean scan-id"
	print "  pci-asv email-latest-attestation \"somebody@issuer.xyz\" \"securityanalyst@company.xyz\" \"Company Inc\" mailrelay.company.xyz"
	print "  asset update"
	print "  agent move"
	print "  agent download"
	print "  policy find-scans"
	print "  scanzone overlaps"
	print "  "

################################################################
# Start of program 
################################################################
#Set debugging on or off
DEBUG=False

#Pull as much information from the environment variables
# as possible, and where missing then initialize the variables.
USETIO=False
USESC=False

#Look for SCHOST or TIOHOST
if os.getenv('SCHOST') is None:
	schost=""
else:
	schost=os.getenv('SCHOST')
	if DEBUG:
		print "Found SCHOST variable:",schost
	USESC=True
if os.getenv('TIOHOST') is None:
	tiohost=""
else:
	tiohost=os.getenv('TIOHOST')
	if DEBUG:
		print "Found TIOHOST variable:",tiohost
	USETIO=True

#If an SCHOST was given, look for a username and password.
#If those are not found, we are not using SecurityCenter
if USESC:
	if os.getenv('SCUSERNAME') is None:
		username=""
		USESC=False
	else:
		username=os.getenv('SCUSERNAME')

	if os.getenv('SCPASSWORD') is None:
		password=""
		USESC=False
	else:
		password=os.getenv('SCPASSWORD')

#If a TIOHOST was given, look for an access key
# and secret key.  If those are not found, we are not using Tenable.io
if USETIO:
	if os.getenv('TIOACCESSKEY') is None:
		accesskey=""
		USETIO=False
	else:
		accesskey=os.getenv('TIOACCESSKEY')

	if os.getenv('TIOSECRETKEY') is None:
		secretkey=""
		USETIO=False
	else:
		secretkey=os.getenv('TIOSECRETKEY')

if USESC == False and USETIO == False:
	print "Unable to determine which system to use.  Please provide credentials for either SecurityCenter or Tenable.io."
	print " "
	print " For SecurityCenter, set these environment variables and export them:"
	print "     SCHOST"
	print "     SCUSERNAME"
	print "     SCPASSWORD"
	print " "
	print " For Tenable.io, set these environment variables and export them:"
	print "     TIOHOST"
	print "     TIOACCESSKEY"
	print "     TIOSECRETKEY"
	print " "
	print " SecurityCenter example:"
	print "     SCHOST=192.168.255.123"
	print "     SCUSERNAME=secmanager"
	print "     SCPASSWORD=mypassword"
	print "     export SCHOST SCUSERNAME SCPASSWORD"
	print " "
	print " Tenable.io example:"
	print "     TIOHOST=cloud.tenable.com"
	print "     TIOACCESSKEY=***********************************************************"
	print "     TIOSECRETKEY=***********************************************************"
	print "     export TIOHOST TIOACCESSKEY TIOSECRETKEY"
	print " "
	exit(-1)


#Get commands
if len(sys.argv) > 1:
	try:
		noun=sys.argv[1]
	except:
		DisplayHelp()
		exit(0)
	if DEBUG:
		print "Noun:",noun
else:
	DisplayHelp()
	exit(0)
	
if len(sys.argv) > 2:
	try:
		verb=sys.argv[2]
	except:
		DisplayHelp()
		exit(0)
	if DEBUG:
		print "Verb:",verb
else:
	verb=""
	
if USESC:
	#Create a session as the user
	try:
		scconn=SecurityCenter5(schost)
	except requests.exceptions.ConnectionError:
		print "Unable to connect to SecurityCenter"
		exit(-1)
	scconn.login(username,password)
	if DEBUG:
		print "Logged in as "+str(username)+" to SecurityCenter at "+str(schost)

if USETIO:
	tioconn = TenableIOClient(access_key=accesskey, secret_key=secretkey)



while True:
	if noun == "help":
		if verb == "":
			DisplayHelp()
			exit(0)
	if noun == "scan":
		if verb == "launch":
			if USESC:
				print "Launching SecurityCenter scan"
				if len(sys.argv) > 3:
					scanname=sys.argv[3]
					if( LaunchScan(scconn,scanname)):
						print "Scan launched"
						exit(0)
					else:
						print "Scan not launched"
						exit(-1)
				else:
					print "Missing arguments"
			if USETIO:
				print "Launching Tenable.io scan"
				#TIO scans require a scan folder name and a scan name to properly tell them apart.
				if len(sys.argv) > 4:
					scanfolder=sys.argv[3]
					scanname=sys.argv[4]
					if( LaunchTioScan(tioconn,scanfolder,scanname) ):
						print "Scan successfully launched"
					else:
						print "Problem launching scan"
					exit(0)
				else:
					print "Missing arguments"
				break

			break
		if verb == "quick":
			if len(sys.argv) > 4:
				scantarget=sys.argv[5]
				repositoryid=sys.argv[4]
				scanpluginid=sys.argv[3]
				scanport=0
				if len(sys.argv) > 6:
					scanport=sys.argv[6]
				if USESC:
					print "Launching a quick scan of",scantarget,"for plugin ID",scanpluginid
					if LaunchRemediationScan(scconn,scanpluginid,repositoryid,scantarget,scanport):
						print "Scan launched"
					else:
						print "Problem launching scan"
					exit(0)
				if USETIO:
					print "Feature not yet implemented for Tenable.io"
			else:
				print "Missing arguments"
		if verb == "stop":
			print "Stopping scan"
			break

		if verb == "stop-all":
			print "Stopping all scans"
			if USETIO:
				print "Stopping all scans in Tenable.io"
				if( StopAllTioScans(tioconn) ):
					print "All scans should be stopped."
					exit(0)
				else:
					print "Problem stopping scan."
					exit(-1)
				break
			break
		#Can either be:
		# tenablecli.py scan pci-submit scan-id
		# tenablecli.py scan pci-submit when-clean scan-id
		if verb == "pci-submit":
			if USESC:
				print "This feature is not available in SecurityCenter"
				break
			if USETIO:
				print "Submitting PCI ASV scan for ASV review."
				if len(sys.argv) > 4:
					if sys.argv[3] == "when-clean":
						scanid=sys.argv[4]
						print "Submitting scan ID",scanid,"if it is clean"
						#Any occurence of plugin 33929 is a failure.  Plugin 33930 is a good sign
						if checkIfPCIASVClean(tioconn,scanid):
							print "Scan is ready for PCI ASV submission"
							uuid=getScanUUID(tioconn,scanid)
							print "Submitting scan UUID",uuid
							submitForPCIASVScanUUID(tioconn,uuid)
						exit(0)
					else:
						print "Unknown arguments"
						exit(-1)
						break
				elif len(sys.argv) > 3:
					scanid=sys.argv[3]
					print "Submitting scan ID",scanid
					print "Scan is ready for PCI ASV submission"
					uuid=getScanUUID(tioconn,scanid)
					print "Submitting scan UUID",uuid
					submitForPCIASVScanUUID(tioconn,uuid)
					exit(0)
				else:
					print "Missing arguments"
					exit(-1)
					break
				
	if noun == "pci-asv":
		#./tenablecli.py pci-asv email-latest-attestation "somebody@issuer.xyz" "securityanalyst@company.xyz" "Company Inc" mailrelay
		if verb == "email-latest-attestation":
			if USESC:
				print "This feature is not available in SecurityCenter"
				break
			if USETIO:
				if len(sys.argv) > 3:
					print "Checking latest PCI ASV attestation"
					uuid=getLatestPCIASVAttestationUUID(tioconn)				
					emailPCIASVAttestation2(tioconn,uuid,sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6])
					#emailPCIASVAttestation3(tiohost,accesskey,secretkey,uuid,sys.argv[3])
					exit(0)
				else:
					print "Need recepients list"
				

			

	if noun == "asset":
		if verb == "update":
			print "Updating asset group"
			grouptype=""
			if( len(sys.argv) > 3 ):
				grouptype=sys.argv[3]
				#Should be in one of these formats for Tenable.io
				# ./tenablecli.py asset update target-group "Target group name" "filterfield1" "operator1" "value1"... "filterfield2" "operator2" "value 2"
				# ./tenablecli.py asset update agent-group "Agent group name" "filterfield1" "operator1" "value1"... "filterfield2" "operator2" "value 2"
				#For SecurityCenter:
				# ./tenablecli.py asset update dynamic-asset-group "Asset group"...
				# ./tenablecli.py asset update static-asset-group "Asset group"...
				# 
				if USETIO:
					if( grouptype == "target-group" ):
						print "Updating target group"
					elif ( grouptype == "agent-group") :
						print "Updating agent group"
					else:
						print "Unknown group type"

				if USESC:
					if( grouptype == "dynamic-asset-group" ):
						print "Updating dynamic asset group"
					elif ( grouptype == "static-asset-group") :
						print "Updating static asset group"
					else:
						print "Unknown group type"
			else:
				print "Missing arguments"
			break

	if noun == "agent":
		if verb == "move":
			print "Moving agent"
			break


		if verb == "download":
			if( len(sys.argv) > 3):
				fileformat=sys.argv[3]
				if fileformat == "csv":
					if USETIO:
						AgentDownloadCSV(tioconn,"agents.csv")
						exit(0)
					if USESC:
						print "Feature not implemented for SecurityCenter"
						break
				else:
					print "Unknown file format"
					break
			else:
				print "Missing arguments"
			break

	if noun == "policy":
		if verb == "find-scans":
			if USETIO:
				if len(sys.argv) > 3:
					policyname=sys.argv[3]
					print "Finding all scans that use policy",policyname
					if( FindTioScansByPolicy(tioconn,policyname) ):
						print "Successfully found all scans"
					else:
						print "Problem finding scans"
					exit(0)
				else:
					print "Missing arguments"
				break

	if noun == "scanzone":
		if USETIO:
			print "Feature not available for Tenable.io, only SecurityCenter"
			break
		if verb == "overlaps":
			CheckForScanZoneOverlaps(scconn)	
			exit(0)
			
	break


print "That function is currently not available"



