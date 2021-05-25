#!/usr/bin/env python
# -*- coding: utf-8 -*-
# LanScan.py
# Scan LAN and Map to CVE
# Description: Collects LAN data and compares to CVEs
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
# Website: www.ripplesoftware.ca
# Github: www.github.com/rippledj/lan_scan

# Import modules
import os
import socket
from netaddr import IPAddress
import netifaces
#https://pypi.org/project/icmplib/
from icmplib import ping, multiping, traceroute, resolve, Host, Hop
#import uuid
from getmac import get_mac_address as gma
from mac_vendor_lookup import MacLookup as mac_lookup
import subprocess
import traceback
import time
from datetime import datetime
import tldextract
from io import BytesIO
import re
from nslookup import Nslookup
import dns.resolver
import random
#https://pypi.org/project/python-nmap/
import nmap
#https://pypi.org/project/python3-nmap/
import nmap3
from pprint import pprint
import pickle
# Import custom classes
import SQLProcessor
import LanScanLogger
import NmapProfiles

# Usesd for ANSI color output
class bcol:
    HEADER = '\033[95m'
    PURPLE = '\033[94m'
    CYAN = '\033[36m'
    GREEN = '\033[92m'
    WARN = '\033[93m'
    YELLOW = '\033[33m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Prints the title art
def print_ascii_title():
    print("""
""" + bcol.YELLOW + """
 (               )   (
 )\\ )   (     ( /(   )\\ )
(()/(   )\\    )\\()) (()/(        )               (  (
 /(_)|(((_)( ((_)\\   /(_)) (  ( /(  (     (     ))\ )(""" + bcol.WARN + """
(_))  )\\ _ )\\ _((_) (_))   )\ )(_)) )\ )  )\ ) /((_|()\\
| |   (_)_\\(_) \| | / __| ((_|(_)_ _(_/( _(_/((_))  ((_)""" + bcol.FAIL + """
| |__  / _ \\ | .` | \__ \/ _|/ _` | ' \\)) ' \)) -_)| '_|
|____|/_/ \\_\\|_|\_| |___/\__|\__,_|_||_||_||_|\___||_|

By: Ripple Software Consulting
Website: https://www.ripplesoftware.ca
Author: Joseph Lee
Email: joseph@ripplesoftware.ca""" + bcol.ENDC + "\n\n")

# Prints PostgreSQL ascii art
def print_postgresql_ascii():
    print(bcol.CYAN + """
  +------------------------+
> |   ____  ______  ___    |
> |  /    )/      \\/   \\   |
> | (     / __    _\\    )  |
> |  \    (/ o)  ( o)   )  |
> |   \_  (_  )   \\ )  /   |
> |     \\  /\\_/    \\)_/    |
> |      \\/  //|  |\\\\      |
> |          v |  | v      |
> |            \__/        |
> |                        |
> |  PostgreSQL 1996-2021  |
> |  25 Years of success   |
> +------------------------+""" + bcol.ENDC)


# Holds the HTTPS headers for any web-servers scanned
class Headers:

    def __init__(self):

        # Set the object nslookup
        self.nslookup = Nslookup()

        # Store headers as dict
        self.headers = {
            "cookies" : []
        }
        # Store entire header string
        self.header_str = ""
        # Store top level domain
        self.tld = None
        # Store subdomain
        self.ext = None
        # Store url with extension
        self.url = None
        # Store the alexa position
        self.position = None
        # Store the http return code
        self.http_code = None
        # Store the nslookup IP address
        self.ip = None
        # Store full nslookup response
        self.ip_full = None
        # Store MX records for domain
        self.mx = []

    # Accept the header stream from pycurl
    def display_header(self, header_line):
        header_line = header_line.decode('iso-8859-1')

        # Append the line to string
        self.header_str = self.header_str + header_line

        # Ignore all lines without a colon
        if ':' not in header_line:
            return

        # Break the header line into header name and value
        h_name, h_value = header_line.split(':', 1)

        # Remove whitespace that may be present
        h_name = h_name.strip()
        h_value = h_value.strip()
        h_name = h_name.lower() # Convert header names to lowercase
        # If line is cookie then append to cookies
        if h_name == 'set-cookie': self.headers['cookies'].append(h_value)
        # Append all other Header name and value.
        else: self.headers[h_name] = h_value

    # Get the http code from header string
    def get_http_return_code(self):
        first_line = self.header_str.split("\n")[0]
        if re.search(r' [\d]{3,}', first_line):
            self.http_code = re.search(r' [\d]{3,}', first_line).group(0)

    # Get the IP from nslookup
    def get_ip(self):
        try:
            # Set the uri with subdomain
            if "www." in self.url: uri = "www." + self.tld
            else: uri = self.tld
            print("-- Looking up IP for: " + uri)
            ip_rec = self.nslookup.dns_lookup(uri)
            if len(ip_rec.answer):
                self.ip = ip_rec.answer[0]
            #if len(ip_rec.response_full):
                #self.ip_full = ip_rec.response_full[0]
        except Exception as e:
            traceback.print_exc()
            logger.error("-- Error getting nslookup for: " + uri)
            logger.error(traceback.format_exc())

    # Get MX records as array
    def get_mx_records(self):
        # Set the uri with subdomain
        if "www." in self.url: uri = "www." + self.tld
        else: uri = self.tld
        print("-- Looking up MX for: " + uri)
        try:
            mx = dns.resolver.query(uri, 'MX')
            if len(mx):
                for item in mx:
                    #print(item.exchange)
                    self.mx.append(str(item.exchange))
        except Exception as e:
            #traceback.print_exc()
            logger.error("-- Error getting MX for: " + uri)
            logger.error(traceback.format_exc())


# Check the user input for request to populate vuln_db
def translate_populate_input(input):
    if input.upper() == "Y": return True
    if input.upper() == "N": return False
    else: return None

# Checks if the database as been installed and notifies the user
def do_database_startup_check(args):
    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")
    required_tables = args['required_tables']
    # Create a database connection
    args['db_conn'] = SQLProcessor.SQLProcess(args['database_args'])
    if args['db_conn'].connect():
        print(required_tables)
        args['database_args']['db_installed'] = args['db_conn'].check_database_installed(required_tables)
        # If database installed, then check if populated
        if args['database_args']['db_installed']:
            print("-- Vulnerability database has been installed...")
            print(required_tables)
            args['database_args']['db_populated'] = args['db_conn'].check_database_populated(required_tables)
            # If database not populated then ask user if they want to populate it
            if args['database_args']['db_populated'] == False:
                print("-- Vulnerability database has not been populated...")
                populate = None
                # Print the elephant for PG
                print_postgresql_ascii()
                while populate == None:
                    populate = translate_populate_input(input( bcol.PURPLE + "Do you want to populate the database (Y/n):>" + bcol.ENDC))
                if populate:
                    try:
                        print("-- Populating vulnerability database...")
                        # Import the Db Populator Module
                        import VulnDbPopulator
                        importer = VulnDbPopulator.VulnDbPopulate(args['database_args'])
                        importer.populate()
                        # Set database as populated
                        args['database_args']['db_populated'] = True
                        # Return the args
                        return args
                    except Exception as e:
                        traceback.print_exc()
                        return args
            else:
                print("-- All vulnerability database tables are populated...")
                return args
        # If the database is not installed
        else:
            print("You must install the database before you can check network scans for vulnerabilities.\nRun the 'postgres_setup.sql' file in the 'res/installation' directory.")
            exit(0)
    else:
        args['db_conn'] = False
        args['database_args']['db_installed'] = False
        return args

# Prints the details of the scan in pretty-format
def print_formatted_scan(args, scans_list, input):
    scan = scans_list[input]
    #print(scan)
    # Check if data was returned by the nmap scan
    if args['lan_info'][scan['intf']]["hosts"][scan["ip"]]["nmap_results"][scan['profile']] is None:
        print(bcol.FAIL + "xx No information returned by scan xx " + bcol.ENDC)
    else:
        pprint(args['lan_info'][scan['intf']]["hosts"][scan["ip"]]["nmap_results"][scan['profile']])

# Return if user wants to scan for vulns
def translate_vuln_check_input(input):
    if input.upper() == "Y":
        return True
    elif input.upper() == "N": return False
    else: return None

# Validate the input for de-serialized scans list
def translate_scans_input(args, scans_list, input):
    if input.isdigit() and int(input) in scans_list:
        if scans_list[int(input)] == None: return 0
        elif scans_list[int(input)] == None: return 1
        print("**input OK**")
        return True
    # Handle quit option
    elif input.upper() == "Q":
        print("TTYL!!")
        exit(0)
    # Handle All option
    elif input.upper() == "A": return "A"
    elif input.upper() == "B": return "B"

# Validate the input for serialized file name
def translate_input(args, ser_list, input):
    if input.isdigit() and int(input) in ser_list:
        return input
    elif input.isdigit():
        print("You cannot use a number as a filename!")
        return False
    else:
        return input + "." + args['serialized_ext']

# Check the host for vulnerabilities
def check_host_for_vulns(args, scans_list):
    print("check_host_for_vulns")
    pass

# Get scan list from args
def get_scans_list_from_args(args):
    scan_list = {}
    i = 0
    # Loop through each found interface
    for intf in args['lan_info']:
        for ip, data in args['lan_info'][intf]['hosts'].items():
            for profile in data['nmap_results']:
                i += 1
                scan_list[i] = { "ip" : ip, "profile" : profile, "intf" : intf}
    return scan_list

# Build a report for the vulnerabilities found
def build_vulnerability_report(args):
    pass

# Prints vuln report to stdout
def print_report_data(args):
    pass

# Checks all found hosts for all vulnerabilities
def check_all_available_hosts_for_vuln(args, scan_list):
    pass

# Prints the scans that have been done for each host
def print_available_scans(scan_list):
    for i, host in scan_list.items():
        print(str(i) + " : " + bcol.CYAN + host["ip"] + bcol.ENDC + bcol.WARN + " - " + host['profile'] + bcol.ENDC)
    # Print the All option
    print(bcol.FAIL + "Q : Quit" + bcol.ENDC)
    # Print the Quit option
    print(bcol.CYAN + "A : Scan all for vulnerabilities" + bcol.ENDC)
    # Print the Back option
    print(bcol.PURPLE + "B : Go back to see available serialized files" + bcol.ENDC)

# Get the client LAN IP address
def get_client_host_info():
    info = {}
    print("-- Retrieving client LAN IP address...")
    info['ip'] = socket.gethostbyname(socket.gethostname())
    print("-- Client LAN IP address: " + bcol.CYAN + info['ip'] + bcol.ENDC)
    print("-- Retrieving client MAC address...")
    info['mac_addr'] = gma().upper()
    print("-- Client LAN MAC address: " + bcol.YELLOW + info['mac_addr'] + bcol.ENDC)
    return info

# Check IP valid
def check_ip_valid(ip):
    # If -6 ipv6 scan or ipv4....
    if re.match(r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b|([a-f0-9:]+:+)+[a-f0-9]+', ip):
        return True
    else: return False

# Check if IP is public or private
def check_ip_public(ip):
    return IPAddress().is_public()

# Get a traceroute to the host
def get_host_traceroute(ip):
    print("-- Getting traceroute for " + bcol.CYAN + ip + bcol.ENDC)
    # Check if the IP is an internal IP or public
    #pid = random.randrange(100)
    if check_ip_valid(ip) and not check_ip_public(ip):
        traceroute = traceroute(ip, count=2, fast=True)
    else:
        print(bcol.FAIL + "xx FAIL: " + + bcol.ENDC + " IP address " + bcol.CYAN + ip + bcol.ENDC + " failed to validate.")
        return None

# Get the MAC of LAN host from IP
def get_host_mac_address(ip, ipv6=False):
    print("-- Finding MAC address for: " + bcol.CYAN + ip + bcol.ENDC + "...")
    if ipv6:
        mac_addr = gma(ip6=ip)
        print("-- MAC address for " + bcol.CYAN + ip + bcol.ENDC + " is " + bcol.PURPLE + mac_addr + bcol.ENDC + "...")
        return mac_addr
    else:
        mac_addr = gma(ip=ip).upper()
        print("-- MAC address for " + bcol.CYAN + ip + bcol.ENDC + " is " + bcol.PURPLE + mac_addr + bcol.ENDC + "...")
        return mac_addr

def get_mac_vendor(mac_addr):
    vendor = mac_lookup().lookup(mac_addr)
    print("-- MAC vendor found for " + mac_addr + ": " + bcol.PURPLE + vendor + bcol.ENDC)
    return vendor

def get_lan_info():
    conn_intf = []
    lan_info_arr = {}
    # Checks if interface is up
    def is_interface_up(interface):
        addr = netifaces.ifaddresses(interface)
        return netifaces.AF_INET in addr
    # Get list of all interfaces
    interfaces = netifaces.interfaces()
    print(interfaces)
    for intf in interfaces:
        print("-- Checking if: " + intf + " is up and running..." )
        if is_interface_up(intf):
            print(bcol.CYAN + "** " + intf + " is up and running..." + bcol.ENDC)
            conn_intf.append(intf)
        else: print(bcol.FAIL + "xx " + intf + " is down and out..." + bcol.ENDC)
    for intf in conn_intf:
        print("-- Getting LAN info for: " + bcol.CYAN + intf + bcol.ENDC)
        addrs = netifaces.ifaddresses(intf)
        lan_info = addrs[netifaces.AF_INET]
        lan_info_arr[intf] = {}
        lan_info_arr[intf] = lan_info[0]
        if "netmask" in lan_info_arr[intf]:
            lan_info_arr[intf]['cidr'] = IPAddress(lan_info_arr[intf]['netmask']).netmask_bits()

    #pprint(lan_info_arr)
    return lan_info_arr

# Generate a host range for the addr and cidr
def generate_host_range(addr, cidr):
    # TODO: fix this to be better
    # Class C network
    if int(cidr) == 24:
        network = addr.split(".")
        network = ".".join(network[0:3]) + ".0/" + str(cidr)
    # Class A network
    elif int(cidr) == 16:
        network = addr.split(".")
        network = ".".join(network[0:2]) + ".0.0/" + str(cidr)
    # Class A network
    elif int(cidr) == 8:
        network = addr.split(".")
        network = network[0] + ".0.0.0/" + str(cidr)
    print("** Network range to scan: " + bcol.CYAN + network + bcol.ENDC)
    return network

# Create a link queue with all site and return
def create_lan_host_list(args):

    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")

    print("-- Scanning for hosts...")
    logger.info("-- Scanning for hosts...")

    # Loop through each found interface
    for intf in args['lan_info']:

        args['lan_info'][intf]['hosts'] = {}

        # Use the IP address and CIDR to generate host range for nmap
        host_range = generate_host_range(args['lan_info'][intf]['addr'], args['lan_info'][intf]['cidr'])

        try:

            if "127.0.0" not in host_range:
                # Use python-nmap to get list of all hosts on network
                lan_hosts = args['nm'].scan(hosts=host_range, arguments='-sn', timeout=10)
                #pprint(lan_hosts)
                # Loop through each host found
                for ip, info in lan_hosts['scan'].items():
                    # Get the domain
                    print("[-- Adding found IP: " + bcol.CYAN + ip + bcol.ENDC + " to the LAN hosts list...]")
                    # Put the found scan nodes on interface
                    args['lan_info'][intf]['hosts'][ip] = info
                    # Get MAC address and MAC vendor
                    args['lan_info'][intf]['hosts'][ip]["mac_addr"] = get_host_mac_address(ip)
                    if 'vendor' in args['lan_info'][intf]['hosts'][ip]:
                        args['lan_info'][intf]['hosts'][ip]['vendor']["mac_vendor"] = get_mac_vendor(args['lan_info'][intf]['hosts'][ip]["mac_addr"])
                    else: print("--No vendor attry found")
                    # Get a traceroute for private hosts
                    if args['is_root']:
                        args['lan_info'][intf]['hosts'][ip]["traceroute"] = get_host_traceroute(ip)
                    else: print(bcol.FAIL + "xx you are not root. Skipping traceroute for hosts." + bcol.ENDC)

        except Exception as e:
            print(bcol.FAIL + "** FAILED ** " + bcol.ENDC + "Nmap scan of LAN host range: " + bcol.CYAN + host_range + bcol.ENDC + "...")
            traceback.print_exc()
            logger.error("** FAILED Nmap scan of LAN host range: " + host_range + " ...")
            logger.error(traceback.format_exc())

    # Return the qq
    print("-- Finished scanning for hosts...")
    logger.info("-- Finished scanning for hosts...")
    return args['lan_info']

# Extract the list of scans to conduct
def get_list_of_scans(filepath):
    final_scan_list = []
    if os.path.exists(filepath) and os.path.isfile(filepath):
        print(bcol.WARN + "** Nmap scan file found: " + filepath + bcol.ENDC)
        with open(filepath, "r") as infile:
            scan_list = infile.readlines()
        for line in scan_list:
            if not line.startswith("#") and line.strip() != "":
                final_scan_list.append(line.strip())
                print("** Added Nmap scan: " + bcol.YELLOW + line.strip() + bcol.ENDC)
        return final_scan_list
    else:
        print(bcol.FAIL + "xx Nmap scan file " + filepath + " not found..." + bcol.ENDC)
        print(bcol.FAIL + "xx Using defaut of Regular scan." + bcol.ENDC)
        return ["Regular scan"]

# Do a full nmap scan of each host in host list
def selected_scan_host_list(args):
    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")
    # Create scanner
    scanner = NmapProfiles.NmapScanner()
    # Get all scans to perform on each host from config file
    scan_profile_list = get_list_of_scans(args['nmap_profiles_file'])

    # Loop through all up interfaces information
    for intf, info in args['lan_info'].items():
        # Do not scan Lookback / localhost
        if "127.0.0." not in info["addr"]:
            # Loop through each found host
            for ip, host_attr in info['hosts'].items():
                args['lan_info'][intf]["hosts"][ip]['nmap_results'] = {}
                # For each scan
                for profile in scan_profile_list:
                    try:
                        scan_data = scanner.scan_with_profile(ip, args['is_root'], profile)
                        args['lan_info'][intf]["hosts"][ip]['nmap_results'][profile] = scan_data
                    except Exception as e:
                        args['lan_info'][intf]["hosts"][ip]['nmap_results'][profile] = None

    return args['lan_info']

# Get a list of serialized files with item numbers
def print_serialized_file_list(ser_list):
    if len(ser_list):
        print( bcol.PURPLE + "** " + str(len(ser_list)) + " Serialized file(s) found ** " + bcol.ENDC + "\n")
        for item, value in ser_list.items():
            print(str(item) + ": " + bcol.WARN + value + bcol.ENDC)
    else: print( bcol.FAIL + "** No serialized files found ** " + bcol.ENDC +  "\nEnter a new file name for serialized data (press [Enter] for default filename).")

# Get a list of serialized files with item numbers
def get_serialized_file_list(args):
    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")
    onlyfiles = [f for f in os.listdir(args['serialized_path']) if os.path.isfile(os.path.join(args['serialized_path'], f))]
    ser_files = {}
    i = 0
    for item in onlyfiles:
        if item.strip().endswith("." + args['serialized_ext']):
            i += 1
            ser_files[i] =  item
    return ser_files

# Get serialized results from file
def get_serialized_results(args, filename):
    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")
    print(bcol.FAIL + "** Retreiving ** " + bcol.ENDC + " serialized results from: " + bcol.CYAN + " " + args['serialized_path'] + filename + bcol.ENDC)
    logger.info("** Retreiving serialized results from: " + args['serialized_path'] + filename)
    new_args = []
    try:
        new_args = pickle.load(open(args['serialized_path'] + filename,'rb'))
        return new_args
    except Exception as e:
        traceback.print_exc()
        return False

def serialize_results(args):
    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")
    logger.info("** Serializing results to: " + args['serialized_file'])
    outfile = open(args['serialized_path'] + args['serialized_file'], "wb")
    pickle.dump(args, outfile)
    outfile.close()

# Parse single Alexa site for
def parse_items_thread(database_args, args, qq):

    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")

    # Create a database connection
    db_conn = SQLProcessor.SQLProcess(database_args)
    db_conn.connect()
    args['db_conn'] = db_conn

    # Create a PyCurl object
    curl = pycurl.Curl()
    # Keep track of the number I'm on
    item_num = args['max_queue_count']

    # Loop through each queue item in qq
    for queue in qq:

        # Pull the queue item off
        list_queue = queue

        # Go through each link in link_queue
        while not list_queue.empty():

            # Get item from queue
            print("[ Process " + str(os.getpid()) + " is picking next item from queue...]")
            item = list_queue.get()
            domain = item["domain"]
            position = item["pos"]

            # Only process if not found in database already
            if args['db_conn'].all_already_scraped(len(args['schemes_and_subdomains']), domain, position) == False:

                for ext in args['schemes_and_subdomains']:

                    # Only process if not found in database already
                    if args['db_conn'].is_already_scraped(ext, domain, position) == False:

                        # Instantiate object
                        data_obj = Headers()

                        # Get headers using pycurl
                        try:

                            # Set some other information in the data object
                            data_obj.tld = domain
                            data_obj.ext = ext.replace("https://","").replace("http://", "")
                            data_obj.url = ext + domain
                            data_obj.position = int(position)

                            print("-- Checking " + ext + domain + " for HTTP headers...")
                            # Set URL value
                            curl.setopt(curl.URL, ext + domain)
                            b_obj = BytesIO()
                            #user_agent = '-H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.2403.89 Safari/537.36"'
                            #command = "curl " + user_agent + " -I https://" + domain
                            #print(command)
                            #output = subprocess.check_output(command, shell=True)
                            curl.setopt(pycurl.FOLLOWLOCATION, args['curl_follow_redirect'])
                            curl.setopt(pycurl.MAXREDIRS, args['curl_max_redirect'])
                            curl.setopt(pycurl.CONNECTTIMEOUT, args['curl_conn_timeout'])
                            curl.setopt(pycurl.TIMEOUT, args['curl_timeout'])
                            curl.setopt(curl.HEADERFUNCTION, data_obj.display_header)
                            curl.setopt(curl.WRITEDATA, b_obj)
                            curl.perform()

                            data_obj.get_http_return_code()
                            data_obj.get_ip()
                            # Only want to do this once since it's for domain and subdomain
                            if "https://" in data_obj.url: data_obj.get_mx_records()
                            #print('Header values:-')
                            #print(data_obj.headers)

                        except Exception as e:
                            data_obj.http_code = 0
                            print("[ ** HTTP header request failed to respond " + ext + domain + "...]")
                            traceback.print_exc()
                            logger.error("[ ** HTTP header request failed to respond " + ext + domain + "...]")
                            logger.error(traceback.format_exc())

                        # Store the results to database
                        args['db_conn'].store_headers_to_database(args, data_obj)
                        if len(data_obj.mx): args['db_conn'].store_mx_to_database(args, data_obj)

                        # Delete the object
                        del data_obj

    # End curl session
    curl.close()
    return

#
# Main function
#
if __name__ == "__main__":

    cwd = os.getcwd()
    app_log_file = cwd + "/lan_scan.log"
    nmap_profiles_file = cwd + "/res/nmap_profiles.txt"
    serialized_path = cwd + "/res/serialized/"
    default_serialized_file = cwd + "/res/lan_scan.ser"
    today_datetime = datetime.today().strftime('%Y-%m-%d')
    # Check if user is root
    if os.geteuid() != 0: is_root = False
    else: is_root = True
    # Log levels
    log_level = 3 # Log levels 1 = error, 2 = warning, 3 = info
    stdout_level = 0 # Stdout levels 1 = verbose, 0 = non-verbose
    # Declare variables
    start_time = time.time()
    just_scanned = False

    # Database args
    database_args = {
        "database_type" : "postgresql", # only postgresql available now
        "host" : "127.0.0.1",
        "port" : 5432, # PostgreSQL port
        "user" : "vuln_db",
        "passwd" : "Bg8G0X5CBNrIDyyH67wLK", # PostgreSQL password
        "db" : "vuln_db",
        "charset" : "utf8"
    }

    # Declare args
    args = {
        "is_root" : is_root,
        "get_serialized" : True,
        "log_level" : log_level,
        "stdout_level" : stdout_level,
        # I/0 Files
        "app_log_file" : app_log_file,
        "nmap_profiles_file" : nmap_profiles_file,
        "serialized_ext" : "ser",
        "serialized_path" : serialized_path,
        "default_serialized_file" : default_serialized_file,
        "database_args" : database_args,
        "required_tables" : [
            "cpe_dictionary",
            "nist_cve"
        ],
        "list_limit" : None,
        "num_threads" : 20,
        "max_queue_count" : 32767,
        "max_count" : 100,
        "curl_conn_timeout" : 10,
        "curl_timeout" : 10,
        "curl_follow_redirect" : True,
        "curl_max_redirect" : 5,
        "use_threading" : True,
        "schemes_and_subdomains" : [
            "http://",
            "http://www.",
            "https://",
            "https://www.",
        ]
    }

    # Setup logger
    LanScanLogger.setup_logger(args['log_level'], app_log_file)
    # Include logger
    logger = LanScanLogger.logging.getLogger("LanScan_Logs")

    # Do a startup check to see if databases are installed
    args = do_database_startup_check(args)

    # Print the title art
    print_ascii_title()
    # Display if user is root
    print("Does user have root privileges?: " + str(is_root))
    logger.warning("User has root: " + str(is_root))

    # Loop whole application
    while True:

        # Get a name for the serialized file
        ser_list = get_serialized_file_list(args)
        print_serialized_file_list(ser_list)
        print("\nEnter item number to retrieve serialized data or a new filename to start a new scan.")
        input_ok = False
        while not input_ok:
            input_ok = translate_input(args, ser_list, input(":>"))

        # The input_ok returned is a new filename, so run scans
        if not input_ok.isdigit():

            # Set the serialized output filename and log
            args['serialized_file'] = input_ok
            print("[ -- Output filename: " + bcol.YELLOW + args['serialized_file'] + bcol.ENDC +  " ]")
            logger.info("[ -- Output filename: " + args['serialized_file'] + " ]")

            # Create a python-nmap instance in args
            args['nm'] = nmap.PortScanner()

            # Create a Queue to hold all sites
            try:
                # Get the Host IP address
                args['host_info'] = get_client_host_info()
                #print(args['host_info'])
                args['lan_info'] = get_lan_info()
                args['lan_info'] = create_lan_host_list(args)
                args['lan_info'] = selected_scan_host_list(args)
                #pprint(args['lan_info'])
                # Serialize the args with results
                serialize_results(args)
                # Set the input_ok so menu system will start
                just_scanned = True
            except Exception as e:
                traceback.print_exc()

            print("-- Finished LAN Scan...")

        # If the serialized file requested exists, set args previous file
        # and start the menu process
        if just_scanned == True or input_ok.isdigit():
            # Start the application to examine scans
            if just_scanned == False:
                filename = ser_list[int(input_ok)]
                args = get_serialized_results(args, filename)
            # Set the current is_root into args
            args['is_root'] = is_root
            # Show menu of scans to output
            scans_list = get_scans_list_from_args(args)
            print_available_scans(scans_list)
            print("\nEnter item number to retrieve scan data and analyze.")
            # Start the menu system
            while True:
                # Check input and quit if requested
                input_ok = translate_scans_input(args, scans_list, input(":>"))
                # If full scan of all hosts requested
                if input_ok == "A":
                    args = check_all_available_hosts_for_vuln(args, scans_list)
                    build_vulnerability_report(args)
                    print_report_data(args)
                    # Show menu of scans to output
                    scans_list = get_scans_list_from_args(args)
                    print_available_scans(scans_list)
                    print("\nEnter item number to retrieve scan data and analyze.")

                # Go back to all available serial files
                elif input_ok == "B":
                    break
                elif input_ok:
                    print_formatted_scan(args, scans_list, input_ok)
                    # Ask user if they want to scan the host for vulnerabilities
                    while True:
                        scan_input = translate_vuln_check_input(input(bcol.WARN + "** Do you want to scan host Nmap results for vulnerabilities? (Y/n) :>" + bcol.ENDC))
                        if scan_input: check_host_for_vulns(args, scans_list, input_ok)
                        if not scan_input:
                            print_available_scans(scans_list)
                            print("\nEnter item number to retrieve scan data and analyze.")
                            break
