#!/usr/bin/python3

import requests
import sys
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

def find_service(port_no):
	f = open("services.csv")
	line = f.readline()
	while line != '':
		if line.count(",") < 11:
			line += f.readline()
		else:
			if line.split(",")[1] == str(port_no):
				f.close()
				return line.split(",")
			line = f.readline()
	f.close()
	return ["Unknown"] * 12

def get_ip_info(ip_address):
	base_url = "http://ip-api.com/json/"
	url_params = "?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,currency,isp,org,as,asname,reverse,mobile,proxy,query"
	response = requests.get(base_url + str(ip_address) + url_params)
	return response.json()

def check_port(ip_address, port_no):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(5)
	try:
		con = s.connect((ip_address, port_no))
		try:
			service_info = find_service(port_no)
			port = str(port_no).ljust(8)
			service_name = (service_info[0][:25] + "..." if len(service_info[0]) >= 28 else service_info[0]).ljust(28)
			service_transport = service_info[2].ljust(9)
			service_desc = (service_info[3][:45] + "..." if len(service_info[3]) >= 48 else service_info[3]).ljust(48)
			print("| %s | %s | %s | %s |" % (port, service_name, service_transport, service_desc))
		except Exception as e:
			print(e)

		con.close()
	except:
		pass

def get_open_ports(ip_address):
	print("+----------+------------------------------+-----------+%s+" % ("-" * 50))
	print("| %s | %s | %s | %s |" % ("Port".ljust(8), "Protocol".ljust(28), "Transport".ljust(9), "Description".ljust(48)))
	print("+----------+------------------------------+-----------+%s+" % ("-" * 50))
	with ThreadPoolExecutor(max_workers = 256) as executor:
		for i in range(1, 1024):
			executor.submit(check_port, ip_address, i)
	print("+----------+------------------------------+-----------+%s+" % ("-" * 50))

def print_dict(d):
	for k, v in d.items():
		print("%-13s: %s" % (k, v))

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: %s ip_address" % sys.argv[0])
	else:
		print("[*] Requesting information from http://ip-api.com")
		ip_info = get_ip_info(str(sys.argv[1]))
		print("[*] Response: ")
		print_dict(ip_info)
		print("\n[*] Scanning %s for open ports (1-1023)" % sys.argv[1])
		get_open_ports(str(sys.argv[1]))
		print("[*] Report Finished for " + sys.argv[1])
