# Lan Scanner

## Introduction

LanScan.py is a vulnerability scanning application. LanScan will populate a PostgreSQL with NIST CVE data feed bulk data files, and NIST CDE Dictionary.  After using Nmap to map and service scan all LAN hosts, it searches the NIST CVE database for CPEs found in the LAN.


## Service Vulnerability Mapping

A cache of regex comparisons for mapping services to **Common Platform Enumeration (CPE)** is taken from *nmap_vulners/http-vulners-regex.json* (**https://github.com/vulnersCom/nmap-vulners**).  When doing an OS or service scan, the results for each host can be compared against the cache to find any potential software or services.  The CPE can then be compared against the Official CPE Dictionary (**https://nvd.nist.gov/products/cpe**) which is stored also stored in the **res** directory.

Another cache of vulnerability data *scipag/vulscan* (**https://github.com/scipag/vulscan**) contains several CSV files.

### Vulnerability Databases in *scipag/vulscan*

The GitHub repository: **https://github.com/scipag/vulscan**

There are the following databases available at the moment:

* scipvuldb.csv - https://vuldb.com
* cve.csv - https://cve.mitre.org
* securityfocus.csv - https://www.securityfocus.com/bid/
* xforce.csv - https://exchange.xforce.ibmcloud.com/
* expliotdb.csv - https://www.exploit-db.com
* openvas.csv - http://www.openvas.org
* securitytracker.csv - https://www.securitytracker.com (end-of-life)
* osvdb.csv - http://www.osvdb.org (end-of-life)


These caches of vulnerability information should be updated regularly.
