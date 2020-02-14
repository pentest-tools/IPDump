#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2019 Adam Bruce
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import requests
import sys
import socket
import ssl
import threading
import io
import os
from concurrent.futures import ThreadPoolExecutor

class Logger:
	"""
	Provides formatting for the custom logger
	"""

	COLOR_DEFAULT: str = "\033[0m"
	COLOR_ERROR: str = "\033[91m"
	COLOR_SUCCESS: str = "\033[92m"
	COLOR_INFO: str = "\033[93m"


	def __init__(self, enabled: bool=True, color: bool=True):
		"""
		Creates a new instance
		"""
		self.enabled: bool = enabled
		self.color: bool = color

	def success(self, msg: str) -> None:
		"""
		Logs a success message
		"""
		if self.enabled:
			if self.color:
				print("{}[+]{} {}".format(self.COLOR_SUCCESS, self.COLOR_DEFAULT, msg))
			else:
				print("[*] {}".format(msg))

	def info(self, msg: str) -> None:
		"""
		Logs a information message
		"""
		if self.enabled:
			if self.color:
				print("{}[+]{} {}".format(self.COLOR_INFO, self.COLOR_DEFAULT, msg))
			else:
				print("[*] {}".format(msg))

	def error(self, msg: str) -> None:
		"""
		Logs a error message
		"""
		if self.enabled:
			if self.color:
				print("{}[+]{} {}".format(self.COLOR_ERROR, self.COLOR_DEFAULT, msg))
			else:
				print("[*] {}".format(msg))

	def no_status(self, msg: str) -> None:
		"""
		Logs a message with no status icon
		"""
		if self.enabled:
			print("    " + msg)

class PortInfo:
	"""
	Stores information about a specific port
	"""

	def __init__(self, port: int, service_name: str, service_transport: str, service_desc: str):
		self.port = port
		self.service_name = service_name
		self.service_transport = service_transport
		self.service_desc = service_desc

class Dumper:
	"""
	Gathers information via APIs and portscanning about a given IP Address, Web Address or Domain
	"""

	def __init__(self, target: str):
		"""
		Creates a new instance
		"""
		self.target: str = target
		self.logger: Logger = Logger(enabled=False, color=True)

	def attach_logger(self, logger: Logger):
		"""
		Attaches a logger to the dumper. This directly outputs to stdout
		"""
		self.logger = logger		

	def get_ip_info(self) -> dict:
		"""
		Retrieve the information about the IP address from ip-api.com
		"""
		base_url: str = "http://ip-api.com/json/"
		url_params: str = "?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,currency,isp,org,as,asname,reverse,mobile,proxy,query"
		self.logger.info("Requesting information from {}".format(base_url))
		response: requests.Response = requests.get(base_url + str(self.target) + url_params)
		if response.status_code != 200:
			self.logger.error("Unable to connect to {} (Code {})".format(base_url, response.status_code))
		else:
			response_json: dict(str, str) = response.json()
			if response_json["status"] == "success":
				self.logger.success("Response from {}:".format(base_url))
				return response.json()
			else:
				self.logger.error("Unable to fetch information from {} (Reason: {})".format(base_url, response_json["message"]))
		return dict()

	def get_ssl_info(self, timeout: int=5) -> dict:
		"""
		Retrieve the SSL certificate from the host
		"""
		ctx: ssl.SSLContext = ssl.create_default_context()
		s: ssl.SSLSocket = ctx.wrap_socket(socket.socket(), server_hostname=str(self.target))
		s.settimeout(timeout)
		try:
			s.connect((str(self.target), 443))
		except Exception as e:
			self.logger.error("Unable to connect to {} (Reason: {})".format(str(self.target), e))
			return dict()

		cert: ssl.SSLObject = s.getpeercert()
		s.close()
		self.logger.success("Certificate: ")
		return dict(cert)

	def get_whois_info(self, timeout: int=5) -> str:
		"""
		Retrieve the whois information for the targetfrom whois.arin.net
		"""
		base_url: str = "whois.arin.net"
		self.logger.info("Sending whois query to {}".format(base_url))
		s: socket.socket 
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((base_url, 43))
		except Exception as e:
			self.logger.error("Unable to connect to {} (Reason: {})".format(str(self.target), e))
			s.close()
			return ""
		
		host_address: str
		try:
			host_address = socket.gethostbyname(self.target)
		except Exception as e:
			self.logger.error("Unable to connect to {} (Reason: {})".format(str(self.target), e))
			s.close()
			return ""

		s.send((host_address + "\r\n").encode())
		response: bytearray = b""
		while True:
			data: bytearray = s.recv(4096)
			response += data
			if not data:
				break

		s.close()
		self.logger.success("Response from {}:".format(base_url))
		return response.decode()

	def __check_port(self, port_no: int, callback, timeout: int=5) -> None:
		"""
		Tests if the given port is open on the target, if it is, the callback function is executed with one argument of type PortInfo
		"""
		s: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		try:
			con: socket.socket = s.connect((self.target, port_no))
			try:
				service_info: list(str) = find_service(port_no)
				port: str = str(port_no)
				service_name: str = service_info[0]
				service_transport: str = service_info[2]
				service_desc: str = service_info[3]
				callback(PortInfo(port, service_name, service_transport, service_desc))
			except Exception as e:
				self.logger.error("Unable to scan port {} (Reason: {})".format(str(port_no), e))
			con.close()
		except Exception as e:
			pass

	def get_open_ports(self, callback, workers: int=100, start: int=1, end: int=1000, timeout: int=5) -> None:
		"""
		Gets the open ports running on the target and prints them as a table.
		"""
		self.logger.info("Portscanning {} for open ports in the range {}-{}".format(self.target, start, end))
		self.logger.no_status("+-------+------------------------------+-----------+%s+" % ("-" * 50))
		self.logger.no_status("| %s | %s | %s | %s |" % ("Port".ljust(5), "Protocol".ljust(28), "Transport".ljust(9), "Description".ljust(48)))
		self.logger.no_status("+-------+------------------------------+-----------+%s+" % ("-" * 50))
		with ThreadPoolExecutor(max_workers=workers) as executor:
			for port in range(start, end+1):
				executor.submit(self.__check_port, port, callback, timeout)

		self.logger.no_status("+-------+------------------------------+-----------+%s+" % ("-" * 50))
		self.logger.success("Portscan finished")


def print_dict(d: dict) -> None:
	"""
	Prints the given dictionary in key-value pairs
	"""
	for k, v in d.items():
		print("%-20s: %s" % (k, v))


def find_service(port_no: int) -> list:
	"""
	Retrieves information about the service running on the given port.
	This information is read from services.csv
	"""

	if os.path.isfile("services.csv"):
		f: io.TextIOWrapper = open("services.csv")
		line: str = f.readline()
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


def print_port_info(portinfo: PortInfo):
	"""
	Prints the information of a port formatted to match the table in Dumper.get_open_ports
	"""
	port = str(portinfo.port).ljust(5)
	service_name = (portinfo.service_name[:25] + "..." if len(portinfo.service_name) >= 28 else portinfo.service_name).ljust(28)
	service_transport = portinfo.service_transport.ljust(9)
	service_desc = (portinfo.service_desc[:45] + "..." if len(portinfo.service_desc) >= 48 else portinfo.service_desc).ljust(48)
	print("    | %s | %s | %s | %s |" % (port, service_name, service_transport, service_desc))

if __name__ == "__main__":
	
	parser = argparse.ArgumentParser()
	parser.add_argument("host", help="The hostname/IP Address, URL or Domain of the target", type=str)
	parser.add_argument("-l", "--no-logging", help="Disable logging", action="count")
	parser.add_argument("-c", "--no-color", help="Disable colored logging", action="count")
	parser.add_argument("-a", "--all", help="Run all tools on the given target", action="count")
	parser.add_argument("-p", "--port-scan", help="Enable portscanning on the target", action="count")
	parser.add_argument("-i", "--ip-info", help="Fetch information from api-ip.com (contains geographical info)", action="count")
	parser.add_argument("-s", "--ssl-cert", help="Retrieves the SSL Certificate of the host", action="count")
	parser.add_argument("-w", "--whois", help="Fetch whois information from arin.net (contains domain ownership info)", action="count")
	parser.add_argument("-n", "--workers", help="Number of workers for portscanning", type=int, default=256)
	parser.add_argument("-r", "--range", help="Range of ports to scan formatted as START-END", type=str, default="1-1024")
	parser.add_argument("-t", "--timeout", help="Timeout for SSL and WHOIS fetching and portscanning", type=int, default=5)
	args = parser.parse_args()
	
	logger: Logger = Logger(enabled=args.no_logging == None, color=args.no_color == None)
	dumper: Dumper = Dumper(args.host)
	
	dumper.attach_logger(logger)

	logger.info("WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software." \
		" For more information see the LICENSE file included with this software.\n")

	if args.all != None or args.ip_info != None:
		print_dict(dumper.get_ip_info())
	if args.all != None or args.ssl_cert != None:
		print_dict(dumper.get_ssl_info(timeout=args.timeout))
	if args.all != None or args.whois != None:
		print(dumper.get_whois_info(timeout=args.timeout))
	if args.all != None or args.port_scan != None:
		dumper.get_open_ports(workers=args.workers, 
			start=int(args.range.split("-")[0]), 
			end=int(args.range.split("-")[1]), 
			callback=print_port_info, 
			timeout=args.timeout)
		
	logger.info("Report for {} completed".format(args.host))
