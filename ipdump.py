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


	def __init__(self, enabled: bool = True, color: bool = True):
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

class Dumper:
	"""
	Gathers information via APIs and portscanning about a given IP Address, Web Address or Domain
	"""

	def __init__(self, target: str, logger: Logger):
		"""
		Creates a new instance
		"""
		self.target: str = target
		self.logger: Logger = logger

	def get_ip_info(self) -> None:
		"""
		Retrieve the information about the IP address from APIs, and print to the terminal
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
				self.print_dict(response.json())
			else:
				self.logger.error("Unable to fetch information from {} (Reason: {})".format(base_url, response_json["message"]))

	def get_ssl_info(self) -> None:
		"""
		Retrieve the SSL certificate from the host
		"""
		ctx: ssl.SSLContext = ssl.create_default_context()
		s: ssl.SSLSocket = ctx.wrap_socket(socket.socket(), server_hostname=str(self.target))
		s.connect((str(self.target), 443))
		cert: ssl.SSLObject = s.getpeercert()
		s.close()
		self.logger.success("Certificate: ")
		self.print_dict(dict(cert))

	def get_whois_info(self) -> None:
		"""
		Retrieve the whois information for the target, and print it to the terminal.
		"""
		base_url: str = "whois.arin.net"
		self.logger.info("Sending whois query to {}".format(base_url))
		s: socket.socket 
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((base_url, 43))
		except Exception as e:
			s.close()
			self.logger.error(e)
			return
		
		host_address: str
		try:
			host_address = socket.gethostbyname(self.target)
		except Exception as e:
			s.close()
			self.logger.error(e)
			return

		s.send((host_address + "\r\n").encode())
		response: bytearray = b""
		while True:
			data: bytearray = s.recv(4096)
			response += data
			if not data:
				break

		s.close()
		self.logger.success("Response from {}:".format(base_url))
		print(response.decode())

	def __check_port(self, port_no: int) -> None:
		"""
		Tests if the given port is open on the target, and prints the relevent table entry
		"""
		s: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		try:
			con: socket.socket = s.connect((self.target, port_no))
			try:
				service_info: list(str) = self.find_service(port_no)
				port: str = str(port_no).ljust(5)
				service_name: str = (service_info[0][:25] + "..." if len(service_info[0]) >= 28 else service_info[0]).ljust(28)
				service_transport: str = service_info[2].ljust(9)
				service_desc: str = (service_info[3][:45] + "..." if len(service_info[3]) >= 48 else service_info[3]).ljust(48)
				print("| %s | %s | %s | %s |" % (port, service_name, service_transport, service_desc))
			except Exception as e:
				self.logger.error(e)
			con.close()
		except Exception as e:
			pass

	def get_open_ports(self, workers: int = 256) -> None:
		"""
		Gets the open ports running on the target and prints them as a table.
		"""
		PORT_MIN = 1
		PORT_MAX = 1024
		self.logger.info("Portscanning {} for open ports in the range {}-{}".format(self.target, PORT_MIN, PORT_MAX))
		print("+-------+------------------------------+-----------+%s+" % ("-" * 50))
		print("| %s | %s | %s | %s |" % ("Port".ljust(5), "Protocol".ljust(28), "Transport".ljust(9), "Description".ljust(48)))
		print("+-------+------------------------------+-----------+%s+" % ("-" * 50))
		with ThreadPoolExecutor(max_workers = workers) as executor:
			for port in range(PORT_MIN, PORT_MAX):
				executor.submit(self.__check_port, port)
		print("+-------+------------------------------+-----------+%s+" % ("-" * 50))
		self.logger.success("Portscan finished")

	@staticmethod
	def print_dict(d: dict) -> None:
		"""
		Prints the given dictionary in key-value pairs
		"""
		for k, v in d.items():
			print("%-20s: %s" % (k, v))

	@staticmethod
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
	parser.add_argument("-n", "--workers", help="Number of workers for portscanning", type=int)
	args = parser.parse_args()
	
	logger: Logger = Logger(enabled=args.no_logging == None, color=args.no_color == None)

	dumper: Dumper = Dumper(args.host, logger)

	logger.info("WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software." \
		" For more information see the LICENSE file included with this software.\n")

	if args.all != None or args.ip_info != None:
		dumper.get_ip_info()
	if args.all != None or args.ssl_cert != None:
		dumper.get_ssl_info()
	if args.all != None or args.whois != None:
		dumper.get_whois_info()
	if args.all != None or args.port_scan != None:
		workers: int = args.workers
		if workers != None:
			dumper.get_open_ports(workers=workers)
		else:
			dumper.get_open_ports()

	logger.info("Report for {} completed".format(args.host))
