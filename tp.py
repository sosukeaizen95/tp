#Make sure the libraries listed here are already installed:

from OTXv2 import OTXv2
import IndicatorTypes
import argparse
import shodan
import sys
import json
import os
import datetime


API_SHODAN='7U7zejnvwVIOZKKMHuVvfVHSVwFhmEga'
API_OTX='166d443873c97e1fefb84c422cfdf0216f92dcef109af3d804a3075ea19beb4b'


def host_query(ip,k_api,name,k_api_1):
	api= shodan.Shodan(k_api)
	host=api.host(ip)
	API_KEY = os.getenv(k_api_1)
	otx = OTXv2(API_KEY)
	ioc=otx.get_indicator_details_full(IndicatorTypes.IPv4,ip)
	t=open(name,"a")
	t.write("\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n")
	t.write("""
************************************************************************************************************************************************************************************

IP: {}
Organization: {}
Operating System: {}
Last Update: {}
Internet Service Provider (ISP): {}
Autonomous System Number (ASN): {}
Country: {}
City: {}
Latitude: {}
Longitude: {}
Hostnames: {}
Domains: {}
Ports: {}
Number of IoC (Indicators of Compromise): {}

""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('last_update','n/a'), host.get('isp','n/a'), host.get('asn','n/a'), host.get('country_name','n/a'), host.get('city','n/a'), host.get('latitude','n/a'), host.get('longitude','n/a'), host.get('hostnames','n/a'), host.get('domains','n/a'), host.get('ports','n/a'), ioc['general']['pulse_info'].get('count','n/a')))
	t.write("\r\n-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_")
	t.write("\r\nPORTS DATA FOR IP: "+host['ip_str'])
	for item in host['data']:
		t.write("\r\n______________________________________________________________")
		t.write("\r\nData information about port %d for ip:" %item['port'])
		t.write(host['ip_str'])
		t.write("""
Port: {}
Banner: {}
Transport: {}
Timestamp: {}
Operating System: {}
Autonomous System Number (ASN): {}
HASH: {}
Internet Service Provider(ISP): {}
""".format(item['port'], item['data'], item['transport'], item['timestamp'], item['os'], item['asn'], item['hash'], item['isp']))
		t.write("\r\n....................")
		try:
			t.write("\r\n                    ")
			t.write("\r\nLocation data about port %d :" %item['port'])
			for loc in item['location']:
				t.write("\r\n"+str(loc)+" : "+str(item['location'][loc]))
			t.write("\r\n....................")
		except:
			t.write("\r\n        ")			
			t.write("\r\n....................")
		try:
			t.write("\r\n                    ")
			t.write("\r\nNTP data about port %d :" %item['port'])
			for ntp in item['ntp']:
				t.write("\r\n"+str(ntp)+" : "+str(item['ntp'][ntp]))
			t.write("\r\n....................")
		except:
			t.write("\r\n        ")
			t.write("\r\n....................")
		try:
			t.write("\r\n                    ")
			t.write("\r\nCloud data about port %d :" %item['port'])
			for clo in item['cloud']:
				t.write("\r\n"+str(clo)+" : "+str(item['cloud'][clo]))
			t.write("\r\n....................")
		except:
			t.write("\r\n        ")	
			t.write("\r\n....................")
		try:
			t.write("\r\n                    ")
			t.write("\r\nShodan data about port %d :" %item['port'])
			for sho in item['_shodan']:
				t.write("\r\n"+str(sho)+" : "+str(item['_shodan'][sho]))

			t.write("\r\n....................")
		except:
			t.write("\r\n        ")
			t.write("\r\n....................")
		try:
			t.write("\r\n                    ")
			t.write("\r\nHostnames data about port %d :" %item['port'])
			for hst in item['hostnames']:
				t.write("\r\n"+str(hst))
			t.write("\r\n....................")
		except:
			t.write("\r\n        ")
			t.write("\r\n....................")
		try:
			t.write("\r\n                    ")
			t.write("\r\nDomains data about port %d :" %item['port'])
			for dmn in item['domains']:
				t.write("\r\n"+str(dmn))
			t.write("\r\n....................")
		except:
			t.write("\r\n        ")
			t.write("\r\n....................")

		t.write("\r\n______________________________________________________________")

	t.write("\r\n-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_")
	t.write("\r\n-_-_-_-_-_-_-_-_-_IoC details_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_")
	try:
		t.write("\r\n                    ")
		t.write("\r\n Pulses data for ip:"+host['ip_str'])
		for pulse in ioc['general']['pulse_info']['pulses']:
			t.write("\r\nId:"+str(pulse['id']))
			t.write("\r\nName:"+str(pulse['name']))
			t.write("\r\nDescription:"+str(pulse['description']))
			t.write("\r\nModified:"+str(pulse['modified']))
			t.write("\r\nCreated:"+str(pulse['created']))
			t.write("\r\nMalware Families")
			for fam in pulse['malware_families']:
				t.write("\r\n	********************")
				t.write("\r\n	Id:"+str(fam['id']))
				t.write("\r\n	Display name:"+str(fam['display_name']))
				t.write("\r\n	Target:"+str(fam['target']))
			t.write("\r\n	********************")

		t.write("\r\n....................")
	except:
		t.write("\r\n        ")
		t.write("\r\n....................")

	t.write("\r\n-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_")
	t.close
	return host

if len(sys.argv) == 1:
	print(os.environ.get('USER','n/a'))
	print('Usage: %s' % sys.argv[0])
	sys.exit(1)


try:
	name="Report_"+datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")+".txt"
	x=open(name,"x")
	x.write("************************************************************************")
	l=len(sys.argv)-1
	x.write("\r\n IP's REPORT (Total=%d)"%l)
	x.write("\r\n ")
	x.write("\r\n Date: "+datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
	x.write("\r\n")
	x.close	

	
	print("wait please!...")
	for ip in range(1,len(sys.argv)):
		ip_adr=sys.argv[ip]
		host=host_query(ip_adr,API_SHODAN,name,API_OTX)
	print("Ok!")
except Exception as e:
	print('Error: %s' % e)
	sys.exit(1)
