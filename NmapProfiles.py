#!/usr/bin/env python
# -*- coding: utf-8 -*-
# LanScan.py
# Scan LAN and Map to CVE
# Description: Conducts a python-nmap scan according to built-in profiles
# and returns results to LanScan.py
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
# Website: www.ripplesoftware.ca
# Github: www.github.com/rippledj/lan_scan
# NOTE: Original code adapted from: https://gist.github.com/angeloped/4f496033dbe50448c576e1343f4d6d12

import os
import re
import nmap
#https://pypi.org/project/python-nmap/
import nmap3
#https://pypi.org/project/python3-nmap/
import traceback
import LanScanLogger
from pprint import pprint

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

class NmapScanner:


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

    def __init__(self):
        """
        name: nmap_profile.py
        author: bryan angelo
        description: A collection of Nmap scan profiles for python-nmap.
        """

        required_root_file = os.getcwd() + "/res/root_profiles.txt"
        self.require_root = self.get_required_root_status_list(required_root_file)

        # List of profiles that can be run with python-nmap
        self.nmap_profiles = {
            ### Misc ###
            "Determine firewall status":[{"ip":""},"-sA {0}"],
            "Scan running devices":[{"ip":""},"-sP {0}"],
            "Detect remote services":[{"ip":""},"-sV {0}"],
            "Scan host using TCP Syn":[{"ip":""},"-PS {0}"],
            "Scan host using TCP Ack":[{"ip":""},"-PA {0}"],
            "Scan host using IP protocol ping":[{"ip":""},"-PO {0}"],
            "Scan host using UDP ping":[{"ip":""},"-PU {0}"],
            "Scan host UDP services":[{"ip":""},"-sU {0}"],
            "Scan for IP protocol":[{"ip":""},"-sO {0}"],


            ### Commonly used TCP ports using TCP SYN Scan ###
            "Stealthy scan":[{"ip":""},"-sS {0}"],
            "OS Fingerprinting":[{"ip":""},"-sT {0}"],
            "Find TCP ports using TCP ACK scan":[{"ip":""},"-sA {0}"],
            "Find TCP ports using TCP Window scan":[{"ip":""},"-sW {0}"],
            "TCP ports using TCP Maimon scan":[{"ip":""},"-sM {0}"],


            ### Scan a firewall for security weakness ###
            "TCP Null Scan to fool a firewall to generate a response":[{"ip":""},"-sN {0}"], # Does not set any bits (TCP flag header is 0)
            "TCP Fin scan to check firewall":[{"ip":""},"-sF {0}"], # Sets just the TCP FIN bit
            "TCP Xmas scan to check firewall":[{"ip":""},"-sX {0}"], # Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree


            ### Firewall Evasion ###
            "Firewall evasion: Fragment packets":[{"ip":""},"-f {0}"],
            "Firewall evasion: Maximum Transmission Unit":[{"ip":""},"--mtu 24 {0}"],
            "Firewall evasion: Decoy addresses":[{"ip":""},"-D RND:10 {0}"],
            "Firewall evasion: Idle zombie":[{"zombie_ip":"","ip":""},"-sI {0} {1}"],
            "Firewall evasion: Source port":[{"source_port":[53,20,67],"ip":""},"--source-port {0} {1}"],
            "Firewall evasion: Append Random Data":[{"ip":""},"--data-length 25 {0}"],
            "Firewall evasion: Scan with Random Order":[{"ip":""},"--randomize-hosts {0}"],
            "Firewall evasion: MAC Address Spoofing":[{"ip":""},"-v -sT -PN --spoof-mac 0 {0}"],
            "Firewall evasion: Send Bad Checksums":[{"ip":""},"--badsum {0}"],


            ### Zenmap Scan Profile ###
            # It comes pre loaded with 10 different scan types which we will take closer look at them in this article.
            # Some of the scan types are kind of obvious, however they may not be to everyone.
            # Timing: -T(x) - Paranoid Sneaky Polite Normal Aggressive Insane
            "Intense scan":[{"-T":[4,0,1,2,3,5],"ip":""},"-T{0} -A -v {1}"],
            "Intense scan plus UDP":[{"-T":[4,0,1,2,3,5],"ip":""},"-sS -sU -T{0} -A -v {1}"],
            "Intense scan, all TCP ports":[{"-T":[4,0,1,2,3,5],"ip":""},"-p 1-65535 -T{0} -A -v {1}"],
            "Intense scan, no ping":[{"-T":[4,0,1,2,3,5],"ip":""},"-T{0} -A -v -Pn {1}"],
            "Ping scan":[{"-T":[4,0,1,2,3,5],"ip":""},"-sn {1}"],
            "Quick scan":[{"-T":[4,0,1,2,3,5],"ip":""},"-T{0} -F {1}"],
            "Quick scan plus":[{"-T":[4,0,1,2,3,5],"ip":""},"-sV -T{0} -O -F -version-light {1}"],
            "Quick traceroute":[{"ip":""},"-sn -traceroute {0}"],
            "Regular scan":[{"ip":""},"{0}"],
            "Slow comprehensive scan":[{"-T":[4,0,1,2,3,5],"ip":""},"-sS -sU -T{0} -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 -script \"default or (discovery and safe)\" {1}"],

            # Nmap Port Selection
            "Scan a single TCP port":[{"port":"","ip":""},"-p {0} {1}"],
            "Scan a range of TCP ports":[{"port_a":"","port_z":"","ip":""},"-p {0}-{1} {2}"],
            "Scan 100 common TCP ports (fast)":[{"ip":""},"-F {0}"],
            "Scan all 65535 TCP ports":[{"ip":""},"-p- {0}"],


            ### Nmap Port Scan types ###
            # Privileged access is required to perform the default SYN scans. If privileges are insufficient a TCP connect scan will be used.
            # A TCP connect requires a full TCP connection to be established and therefore is a slower scan.
            # Ignoring discovery is often required as many firewalls or hosts will not respond to PING, so could be missed unless you select the -Pn parameter.
            # Of course this can make scan times much longer as you could end up sending scan probes to hosts that are not there.
            "Scan using TCP connect":[{"ip":""},"-sT {0}"],
            "Scan using TCP SYN scan (default)":[{"ip":""},"-sS {0}"],
            "Scan a single UDP port":[{"port":"","ip":""},"-sU -p {0} {1}"],
            "Scan a range of UDP ports":[{"port_a":"","port_z":"","ip":""},"-sU -p {0}-{1} {2}"],
            "Scan all 65535 UDP ports":[{"ip":""},"-sU -p- {0}"],
            "Scan selected ports - ignore discovery":[{"ip":""},"-Pn -F {0}"],


            ### Service and OS Detection ###
            # Service and OS detection rely on different methods to determine the operating system or service running on a particular port.
            # The more aggressive service detection is often helpful if there are services running on unusual ports.
            # On the other hand the lighter version of the service will be much faster as it does not really attempt to detect the service simply grabbing the banner of the open service.
            "Detect OS and Services":[{"ip":""},"-A {0}"],
            "Standard service detection":[{"ip":""},"-sV {0}"],
            "Insane service detection":[{"ip":""},"-sV --version-intensity 9 {0}"],
            "Aggressive service detection":[{"ip":""},"-sV --version-intensity 5 {0}"],
            "Lighter banner grabbing detection":[{"ip":""},"-sV --version-intensity 0 {0}"],


            ### Digging deeper with NSE Scripts ###
            # According to my Nmap install there are currently 581 NSE scripts. The scripts are able to perform a wide range of security related testing and discovery functions.
            # If you are serious about your network scanning you really should take the time to get familiar with some of them.
            # You will notice I have used the -sV service detection parameter. Generally most NSE scripts will be more effective and you will get better coverage by including service detection.
            "Scan using default safe scripts":[{"ip":""},"-sV -sC {0}"],
            "Scan using a specific NSE script":[{"ip":""},"-sV -p 443 --script=ssl-heartbleed.nse {0}"],
            "Scan with a set of scripts":[{"ip":""},"-sV --script=smb* {0}"],


            ### A scan to search for DDOS reflection UDP services ###
            # UDP based DDOS reflection attacks are a common problem that network defenders come up against.
            # This is a handy Nmap command that will scan a target list for systems with open UDP services that allow these attacks to take place.
            "Scan for UDP DDOS reflectors":[{"ip":""},"nmap -sU -A -PN -n -pU:19,53,123,161 --script=ntp-monlist,dns-recursion,snmp-sysdescr {0}/24"],


            ### HTTP Service Information ###
            # There are many HTTP information gathering scripts, here are a few that are simple but helpful when examining larger networks.
            # Helps in quickly identifying what the HTTP service that is running on the open port. Note the http-enum script is particularly noisy.
            # It is similar to Nikto in that it will attempt to enumerate known paths of web applications and scripts.
            # This will inevitably generated hundreds of 404 HTTP responses in the web server error and access logs.
            "Gather page titles from HTTP services":[{"ip":""},"--script=http-title {0}/24"],
            "Get HTTP headers of web services":[{"ip":""},"--script=http-headers {0}/24"],
            "Find web apps from known paths":[{"ip":""},"--script=http-enum {0}/24"],


            ### Detect Heartbleed SSL Vulnerability ###
            # Heartbleed detection is one of the available SSL scripts.
            # It will detect the presence of the well known Heartbleed vulnerability in SSL services.
            # Specify alternative ports to test SSL on mail and other protocols (Requires Nmap 6.46).
            "Heartbleed testing":[{"ip":""},"-sV -p 443 --script=ssl-heartbleed {0}/24"],


            ### IP Address information ###
            # Gather information related to the IP address and netblock owner of the IP address.
            # Uses ASN, whois and geoip location lookups.
            "Find Information about IP address":[{"ip":""},"--script=asn-query,whois,ip-geolocation-maxmind {0}/24"]
        }

        # List of profiles that can be run with python3-nmap
        self.nmap3_profiles = {

            "DNS Brute Force Script":[{"function":"nmap_dns_brute_script"}]

        }

    # Get required root files
    def get_required_root_status_list(self, filename):
        require_root = []
        with open(filename, "r") as infile:
            contents = infile.readlines()
        for line in contents:
            require_root.append(line.strip())
        return require_root

    # Check IP valid
    def check_ip_valid(self, ip):
        # If -6 ipv6 scan or ipv4....
        if re.match(r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b|([a-f0-9:]+:+)+[a-f0-9]+', ip):
            return True
        else: return False

    # Scan with reqested profile
    def scan_with_profile(self, ip, is_root, profile=None):
        # Include logger
        logger = LanScanLogger.logging.getLogger("LanScan_Logs")

        # Set to regular scan if none provided
        if not bool(profile):
            profile = "Regular scan"

        # Check the IP address is valid
        if self.check_ip_valid(ip):
            # Look for profile in class members
            if profile in self.nmap_profiles:
                try:
                    # Check if scan requries root and if user is root
                    if not profile in self.require_root or (profile in self.require_root and is_root == False):

                        # Print to stdout and log
                        print("-- Starting Nmap Scan: " + self.bcol.WARN + profile + self.bcol.ENDC  + " against IP: " + self.bcol.CYAN + ip + self.bcol.ENDC)
                        logger.info("-- Starting Nmap Scan: " + profile + " against IP: " + ip)

                        #
                		# Profile configurator
                        #
                        profile_c = self.nmap_profiles[profile]
                        for arg_k,arg_d in profile_c[0].items():
                            # Set ip address
                            profile_c[0]["ip"] = ip

                			# Config input
                            if isinstance(arg_d, list):
                                while not bool(len(profile_c[0][arg_k])):
                                    profile_c[0][arg_k] = input("Choose [{0}] for {1}: ".format(",".join([str(d) for d in arg_d]), arg_k))

                					# Select the first one if none
                                    if not bool(profile_c[0][arg_k]):
                                        profile_c[0][arg_k] = arg_d[0]

                            elif not bool(profile_c[0][arg_k]):
                                profile_c[0][arg_k] = input("Set {0}: ".format(arg_k))

                			# Set argument if arg is empty
                            if not bool(profile_c[0][arg_k]):
                                profile_c[0][arg_k] = arg_d

                        #
                        # Do the scan
                        #
                        try:
                            nm = nmap.PortScanner()
                        	#nm = nmap.PortScannerYield()
                            #print(profile_c[1].format(*profile_c[0].values()))
                            scan_data =  nm.scan(arguments=profile_c[1].format(*profile_c[0].values()))
                            pprint(scan_data['scan'])

                            print(self.bcol.FAIL + "-- FINISHED" + self.bcol.ENDC + " Nmap Scan: " + self.bcol.WARN + profile + self.bcol.ENDC  + " against IP: " + self.bcol.CYAN + ip + self.bcol.ENDC)
                            logger.error("-- FINISHED Nmap Scan: " + profile + " against IP: " + ip)
                            return scan_data['scan']

                        # If scan failed then return exception string
                        except Exception as e:
                            traceback.print_exc()
                            logger.error("** Nmap scan: " + profile + " FAILED to complete")
                            logger.error(traceback.format_exc())
                            return traceback.format_exc()

                    else:
                        print("WARNING: " + bcol.CYAN + profile + bcol.ENDC + " requires " + bcol.FAIL + " root " + bcol.ENDC + " privileges.\nYou must use: " + bcol.FAIL + "sudo LanScan.py " + bcol.ENDC + "to run this scan.")
                        logger.error("WARNING: " + profile + " requires root privileges. You must use: 'sudo LanScan.py' to run this scan.")
                        return False
                except Exception as e:
                    traceback.print_exc()
            else:
                print("ERROR: Unidentified command.")
                logger.error("ERROR: '" + profile + "' is an unidentified command.")
                return False
        else:
            print("ERROR: Invalid IP address.")
            logger.error("ERROR: '" + ip + "' is not a valid IPv4 address.")
            return False

def check_if_root_caused_fail(traceback_string):
    lines = traceback_string.splitlines()
    print(lines[-1])
    if "requires root" in lines[-1]:
        print("Requires Root")
        return True
    else: return False

#
# Main Function
#
if __name__ == "__main__":

    requires_root = []
    user = []

    #with open("res/root.txt", "r") as infile:
        #contents = infile.readlines()
    #with open("res/no_root.txt", "r") as infile:
        #contents += infile.readlines()
    #with open("res/no_complete.txt", "r") as infile:
        #contents += infile.readlines()
    #finished_profiles = []
    #for line in contents:
        #finished_profiles.append(line.strip())

    # Example IP address
    ip = "192.168.2.1"
    nm = nmap.PortScanner()
    #nm = nmap3.Nmap()
    scanner = NmapScanner()

    # show profiles
    for profile in scanner.nmap_profiles:
        print(scanner.bcol.FAIL + "-- SCANNING WITH PROFILE : " + profile + " --" + scanner.bcol.ENDC)
        if profile ==  "Detect remote services" :
    		# profile configurator
            profile_c = scanner.nmap_profiles[profile]
            for arg_k,arg_d in profile_c[0].items():
    			# set ip address
                profile_c[0]["ip"] = ip

                # config input
                if isinstance(arg_d, list):
                    while not bool(len(profile_c[0][arg_k])):
                        profile_c[0][arg_k] = input("Choose [{0}] for {1}: ".format(",".join([str(d) for d in arg_d]), arg_k))

    					# select the first one if none
                        if not bool(profile_c[0][arg_k]):
                            profile_c[0][arg_k] = arg_d[0]
                elif not bool(profile_c[0][arg_k]):
                    profile_c[0][arg_k] = input("Set {0}: ".format(arg_k))

    			# set argument if arg is empty
                if not bool(profile_c[0][arg_k]):
                    profile_c[0][arg_k] = arg_d

        	#nm = nmap.PortScannerYield()
        	#print(profile_c[1].format(*profile_c[0].values()))
            try:
                scan = nm.scan(arguments=profile_c[1].format(*profile_c[0].values()))
                pprint(scan)
                #print(nm.csv())
                user.append(profile)
                print(user)
            except Exception as e:
                #traceback.print_exc()
                lines = traceback.format_exc().splitlines()
                if "root" in lines[-1]:
                    print("Requries root")
                    requires_root.append(profile)
                    print(requires_root)
                else:
                    print("Failed but no root required")
                    traceback.print_exc()
                    user.append(profile)
                    print(user)
        else:
            print("ERROR: Unidentified command.")
