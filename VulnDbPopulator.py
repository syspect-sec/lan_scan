#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Lan Scan VulnDbPopulator
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
# Website: www.ripplesoftware.ca
# Github: www.github.com/rippledj/lan_scan

import os
from os import listdir
from os.path import isfile, join
import re
import psycopg2
import traceback
import json
import urllib
from lxml import etree
import ssl
import zipfile
from io import BytesIO
from urllib.request import urlopen
from urllib.parse import unquote
from pprint import pprint
import datetime
import shutil
import hashlib

import LanScanLogger
import SQLProcessor

class VulnDbPopulate:

    # Initialize the class
    def __init__(self, db_args):

        # Import logger to object
        self.logger = LanScanLogger.logging.getLogger("LanScan_Logs")

        # Define the resource directories for downloads and pre-downloaded files
        self.cwd = os.getcwd() + "/"
        self.downloads_dirpath = self.cwd + "res/downloads/"
        self.cve_resources = self.cwd + "res/installation/nist_cve/"
        self.cpe_resources = self.cwd + "res/installation/cpe_dictionary/"

        # Years for start of NIST CVE data
        self.nist_cve_start_year = 2002
        self.current_year = datetime.datetime.now().year

        #
        # URLs and filenames to download CVE and CPE data
        #
        # CVE urls and local filepaths
        self.nist_cve_feed_url = "https://nvd.nist.gov/vuln/data-feeds"
        self.nist_cve_json_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
        self.local_cve_file = "nvdcve-1.1-{year}.json.zip"
        # Metadata, modified, and recent urls
        self.nist_cve_meta_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.meta"
        self.nist_cve_modified_url  = "https://nvd.nist.gov/feeds/xml/cve/trans/es/nvdcve-modifiedtrans.xml.zip"
        self.nist_cve_recent_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
        self.cve_rss_feed = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
        self.vendor_comments = "https://nvd.nist.gov/feeds/xml/cve/misc/vendorstatements.xml.zip"
        # List of all local pre-downoaded CVE data feed files
        self.all_local_cve_files = [f for f in listdir(self.cve_resources) if isfile(join(self.cve_resources, f))]
        # List of all data-feed files up to 2021
        self.cve_feed_files = [
            "vdcve-1.1-2002.json.zip",
            "vdcve-1.1-2003.json.zip",
            "vdcve-1.1-2004.json.zip",
            "vdcve-1.1-2005.json.zip",
            "vdcve-1.1-2006.json.zip",
            "vdcve-1.1-2007.json.zip",
            "vdcve-1.1-2008.json.zip",
            "vdcve-1.1-2009.json.zip",
            "vdcve-1.1-2010.json.zip",
            "vdcve-1.1-2011.json.zip",
            "vdcve-1.1-2012.json.zip",
            "vdcve-1.1-2013.json.zip",
            "vdcve-1.1-2014.json.zip",
            "vdcve-1.1-2014.json.zip",
            "vdcve-1.1-2015.json.zip",
            "vdcve-1.1-2016.json.zip",
            "vdcve-1.1-2017.json.zip",
            "vdcve-1.1-2018.json.zip",
            "vdcve-1.1-2019.json.zip",
            "vdcve-1.1-2020.json.zip",
            "vdcve-1.1-2021.json.zip"
        ]

        # CPE urls and local filepaths
        self.nist_cpe_dict_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/"
        self.local_cpe_filename = "official-cpe-dictionary_v{version}.xml.zip"
        self.cpe_22_filename = "official-cpe-dictionary_v2.2.xml.zip"
        self.cpe_23_filename = "official-cpe-dictionary_v2.3.xml.zip"
        self.cpe_dictionary_files = [
            "official-cpe-dictionary_v2.2.xml.zip",
            "official-cpe-dictionary_v2.3.xml.zip"
        ]

        # Get a PostgreSQL database connection
        self.db_conn = SQLProcessor.SQLProcess(db_args)
        self.db_conn.connect()

    # Populate the database with vuln_db data
    def populate(self):

        #
        # Populate NIST CVE data feed files
        #

        # Loop through start year to current year for bulk files
        for year in range(self.nist_cve_start_year, self.current_year + 1):
        #while False:
            # Set a flag to for if files can be downloaded
            cve_links_found = False

            print("** Populating " + str(year) + " CVE data with downloaded file...")
            self.logger.info("** Populating " + str(year) + " CVE data with downloaded file...")

            try:
                attempts = 0
                success = False
                while attempts < 2 and success == False:
                    # Download annualized file to downloads dir
                    download_success = self.download_annualized_zip_file(year)
                    if download_success:
                        # Get CVE filename
                        cve_file = self.local_cve_file.replace("{year}", str(year))
                        # Get the json object from download filepath
                        json_obj = self.get_json_obj_from_zip_filepath(self.downloads_dirpath + cve_file)
                        # Loop through all items
                        for item in json_obj['CVE_Items']:
                            # Send the single item to the parser
                            cve_item = self.extract_json_item_from_bulk(item, cve_file)
                            # Insert CVE item to database
                            self.db_conn.insert_cve_item(cve_item)
                        # Finally set the flag to not use pre-downloaded files
                        success = True
                        cve_links_found = True
                    # IF file failed to download
                    else:
                        # Delete the failed zip file
                        os.remove(self.downloads_dirpath + cve_file)
                        attempts += 1
                        # Finally set the flag to not use pre-downloaded files
                        cve_links_found = False

            # If any error while parsing pre-downloaded files
            except Exception as e:
                cve_links_found = False
                print("xx Error populating " + str(year) + " CVE data with downloaded file...")
                self.logger.error("xx Error populating " + str(year) + " CVE data with downloaded file...")
                traceback.print_exc()
                self.logger.error(traceback.format_exc())
                exit(1)

            # If CVE data could not be downloaded from internet
            if not cve_links_found:

                print("-- Populating " + str(year) + " CVE data with pre-downloaded file...")
                self.logger.info("-- Populating " + str(year) + " CVE data with pre-downloaded file...")

                try:
                    # Get all files in CVE resource directory
                    cve_file = self.cve_resources + self.local_cve_file.replace("{year}", str(year))
                    if re.match(r'nvdcve-[\d]{1,}\.[\d]\-[\d]{4,}\.json\.zip', cve_file):

                        # Get the json object from filepath
                        json_obj = self.get_json_obj_from_zip_filepath(self.cve_resources + cve_file)
                        # Loop through all items
                        for item in json_obj['CVE_Items']:
                            # Send the single item to the parser
                            cve_item = self.extract_json_item_from_bulk(item, cve_file)
                            # Insert CVE item to database
                            self.db_conn.insert_cve_item(cve_item)

                # If any error while parsing pre-downloaded files
                except Exception as e:
                    print("-- Populating " + str(year) + " CVE data with pre-downloaded file...")
                    traceback.print_exc()
                    self.logger.info("-- Populating " + str(year) + " CVE data with pre-downloaded file...")
                    self.logger.error(traceback.format_exc())

        #
        # Populate NIST CPE data feed files
        #

        # Loop through all required CPE dictionary files
        for cpe_file in self.cpe_dictionary_files:

            # Set a flag to for if files can be downloaded
            cpe_links_found = False

            # Set the cpe_version
            if "2.2" in cpe_file: cpe_version = 2.2
            elif "2.3"in cpe_file: cpe_version = 2.3

            # Check the NIST CPE dictionary for .zip files
            print("** Populating " + cpe_file + " CPE dictionary with downloaded file...")
            self.logger.info("** Populating " + cpe_file + " CPE dictionary with downloaded file...")

            try:
                attempts = 0
                success = False
                while attempts < 2 and success == False:
                    # Download annualized file to downloads dir
                    download_success = self.download_cpe_dict_zip_file(cpe_version)
                    if download_success:
                        print("-- Processing downloaded CPE version" + str(cpe_version) + ".zip file.")
                        self.logger.info("-- Processing downloaded CPE version" + str(cpe_version) + ".zip file.")
                        # Get XML from downloaded file
                        # Unzip the downloaded file
                        if cpe_file.endswith(".zip"):
                            infile = open(self.downloads_dirpath + cpe_file, "rb")
                            zip = zipfile.ZipFile(BytesIO(infile.read()))
                            file = zip.namelist()[0]
                            # Read data from zip package
                            xml = zip.open(file, "r").read()
                        print("-- XML extracted from CPE version " + str(cpe_version) + ".zip file.")
                        self.logger.info("-- XML extracted from CPE version " + str(cpe_version) + ".zip file.")
                        # Extract all CPE items from XML string
                        self.get_cpe_items_from_xml(cpe_file, cpe_version, xml)
                        # Finally set the flag to not use pre-downloaded files
                        success = True
                        cpe_links_found = True
                    # IF file failed to download
                    else:
                        # Delete the failed zip file
                        os.remove(self.downloads_dirpath + cpe_file)
                        attempts += 1
                        # Finally set the flag to not use pre-downloaded files
                        cpe_links_found = False

            # If any error while parsing pre-downloaded files
            except Exception as e:
                cpe_links_found = False
                print("xx Error populating " + cpe_file + " CPE data with downloaded file...")
                self.logger.error("xx Error populating " + cpe_file + " CPE data with downloaded file...")
                traceback.print_exc()
                self.logger.error(traceback.format_exc())

            # If not available then revert to pre-downloaded copy
            if not cpe_links_found:
                print("-- Populating CPE data with pre-downloaded file...")
                try:
                    # Unzip the pre-downloaded file
                    if cpe_file.endswith(".zip"):
                        infile = open(self.cpe_resources + cpe_file, "rb")
                        zip = zipfile.ZipFile(BytesIO(infile.read()))
                        file = zip.namelist()[0]
                        xml = zip.open(file, "r").read()
                    elif ".xml" in cpe_file:
                        infile = open(self.cpe_resources + cpe_file, "rb")
                        xml = infile.read()
                        infile.close()

                    # Extract all CPE items from XML string
                    self.get_cpe_items_from_xml(cpe_file, cpe_version, xml)

                except Exception as e:
                    traceback.print_exc()
                    exit(1)

            print("-- Completed Populating CPE data...")

    # Extract data object from cve-item json
    def extract_json_item_from_bulk(self, item, cve_file):

        # Prepare the dict to hold items
        cve_item = {}

        # CVE Filename
        cve_item['file_name'] = cve_file.split(".")[0]

        # CVE Metadata
        cve_item['data_version'] = item['cve']['data_version']
        cve_item['cve_id'] = item['cve']['CVE_data_meta']['ID']
        cve_item['assigner'] = item['cve']['CVE_data_meta']['ASSIGNER']
        #print("-- Collecting information for CVE: " + cve_item['cve_id'] + "...")

        # CVE Problem Types (Stored as string array)
        cve_item['problem_types'] = []
        for problem_item in item['cve']['problemtype']['problemtype_data']:
            for value in problem_item['description']:
                cve_item['problem_types'].append(value['value'].replace("{", "").replace("}", ""))

        # CVE References (Stored as JSON array)
        cve_item['info_references'] = []
        for reference in item['cve']['references']['reference_data']:
            cve_item['info_references'].append(reference)
        cve_item['info_references'] = json.dumps(cve_item['info_references'])

        # CVE Description (Stored as sring array)
        cve_item['descriptions'] = []
        for description in item['cve']['description']['description_data']:
            cve_item['descriptions'].append(description['value'])

        # CVE Data version
        cve_item['cve_data_version'] = item['configurations']['CVE_data_version']

        # CPE Metadata (Stored as JSON array)
        cve_item['cpe_23_uri_nodes'] = []
        for node in item['configurations']['nodes']:
            cve_item['cpe_23_uri_nodes'].append(node)
        cve_item['cpe_23_uri_nodes'] = json.dumps(cve_item['cpe_23_uri_nodes'])

        # CVSS V3 Metadata
        #pprint(item['impact'])
        if 'baseMetricV3' in item['impact']:
            cve_item['v3_cvss_version'] = item['impact']['baseMetricV3']['cvssV3']['version']
            cve_item['v3_vector_string'] = item['impact']['baseMetricV3']['cvssV3']['vectorString']
            cve_item['v3_attack_vector'] = item['impact']['baseMetricV3']['cvssV3']['attackVector']
            cve_item['v3_attack_complexity'] = item['impact']['baseMetricV3']['cvssV3']['attackComplexity']
            cve_item['v3_privileges_required'] = item['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
            cve_item['v3_user_interaction'] = item['impact']['baseMetricV3']['cvssV3']["userInteraction"]
            cve_item['v3_scope'] = item['impact']['baseMetricV3']['cvssV3']["scope"]
            cve_item['v3_confidentiality_impact'] = item['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
            cve_item['v3_integrity_impact'] = item['impact']['baseMetricV3']['cvssV3']['integrityImpact']
            cve_item['v3_availability_impact'] = item['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
            cve_item['v3_base_score'] = item['impact']['baseMetricV3']['cvssV3']['baseScore']
            cve_item['v3_base_severity'] = item['impact']['baseMetricV3']['cvssV3']["baseSeverity"]

            cve_item['v3_exploitability_score'] = item['impact']['baseMetricV3']["exploitabilityScore"]
            cve_item['v3_impact_score'] = item['impact']['baseMetricV3']["impactScore"]
        else:
            cve_item['v3_cvss_version'] = None
            cve_item['v3_vector_string'] = None
            cve_item['v3_attack_vector'] = None
            cve_item['v3_attack_complexity'] = None
            cve_item['v3_privileges_required'] = None
            cve_item['v3_user_interaction'] = None
            cve_item['v3_scope'] = None
            cve_item['v3_confidentiality_impact'] = None
            cve_item['v3_integrity_impact'] = None
            cve_item['v3_availability_impact'] = None
            cve_item['v3_base_score'] = None
            cve_item['v3_base_severity'] = None

            cve_item['v3_exploitability_score'] = None
            cve_item['v3_impact_score'] = None

        # CVSS V2 Metadata
        if 'baseMetricV2' in item['impact']:
            cve_item['v2_cvss_version'] = item['impact']['baseMetricV2']['cvssV2']['version']
            cve_item['v2_vector_string'] = item['impact']['baseMetricV2']['cvssV2']['vectorString']
            cve_item['v2_access_vector'] = item['impact']['baseMetricV2']['cvssV2']['accessVector']
            cve_item['v2_access_complexity'] = item['impact']['baseMetricV2']['cvssV2']['accessComplexity']
            cve_item['v2_authentication'] = item['impact']['baseMetricV2']['cvssV2']['authentication']
            cve_item['v2_confidentiality_impact'] = item['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
            cve_item['v2_integrity_impact'] = item['impact']['baseMetricV2']['cvssV2']['integrityImpact']
            cve_item['v2_availability_impact'] = item['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
            cve_item['v2_base_score'] = item['impact']['baseMetricV2']['cvssV2']['baseScore']

            cve_item['v2_severity'] = item['impact']['baseMetricV2']["severity"]
            cve_item['v2_exploitability_score'] = item['impact']['baseMetricV2']["exploitabilityScore"]
            cve_item['v2_impact_score'] = item['impact']['baseMetricV2']["impactScore"]
            try: cve_item['v2_ac_insufficient_info'] = item['impact']['baseMetricV2']["acInsufInfo"]
            except: cve_item['v2_ac_insufficient_info'] = None
            cve_item['v2_obtain_all_privilege'] = item['impact']['baseMetricV2']["obtainAllPrivilege"]
            cve_item['v2_obtain_user_privilege'] = item['impact']['baseMetricV2']["obtainUserPrivilege"]
            cve_item['v2_obtain_other_privilege'] = item['impact']['baseMetricV2']["obtainOtherPrivilege"]

            try: cve_item['v2_user_interaction_required'] = item['impact']['baseMetricV2']["userInteractionRequired"]
            except: cve_item['v2_user_interaction_required'] = None
        else:
            cve_item['v2_cvss_version'] = None
            cve_item['v2_vector_string'] = None
            cve_item['v2_access_vector'] = None
            cve_item['v2_access_complexity'] = None
            cve_item['v2_authentication'] = None
            cve_item['v2_confidentiality_impact'] = None
            cve_item['v2_integrity_impact'] = None
            cve_item['v2_availability_impact'] = None
            cve_item['v2_base_score'] = None

            cve_item['v2_severity'] = None
            cve_item['v2_exploitability_score'] = None
            cve_item['v2_impact_score'] = None
            cve_item['v2_ac_insufficient_info'] = None
            cve_item['v2_obtain_all_privilege'] = None
            cve_item['v2_obtain_user_privilege'] = None
            cve_item['v2_obtain_other_privilege'] = None
            cve_item['v2_user_interaction_required'] = None

        # Return the cve_item
        return cve_item

    # Get JSON object from
    def get_json_obj_from_zip_filepath(self, filepath):

        print("-- Extacting json from: " + filepath)
        self.logger.info("-- Extacting json from: " + filepath)
        try:
            # Check for the file that mathces the year iteration
            infile = open(filepath, "rb")
            zip = zipfile.ZipFile(BytesIO(infile.read()))
            infile.close()
            file = zip.namelist()[0]
            contents = zip.open(file, "r").read()
            json_obj = json.loads(contents)

            # Return json obj
            return json_obj
        # Hand exception extracting json object
        except Exception as e:
            print("-- Failed extacting json from: " + filepath)
            self.logger.info("-- Failed extacting json from: " + filepath)
            traceback.print_exc()
            return False

    # Get version specific CPE dictionary zip file
    def download_cpe_dict_zip_file(self, cpe_version):

        # Create the local .zip filepath for the year submitted
        local_zip_filepath = self.downloads_dirpath + self.local_cpe_filename.replace("{version}", str(cpe_version))

        # Check if file downloaded already
        if os.path.exists(local_zip_filepath):
            print("-- Using previously downloaded CPE " + str(cpe_version) + " dictionary resource...")
            self.logger.info("-- Using previously downloaded CPE " + str(cpe_version) +  " dictionary resource...")
            # Return success
            return True
        else:
            # Try to download the resource
            print("-- Downloading CPE " + str(cpe_version) + " dictionary resource...")
            self.logger.info("-- Downloading CPE " + str(cpe_version) + " dictionary resource...")
            try:
                url = self.nist_cpe_dict_url + self.local_cpe_filename.replace("{version}", str(cpe_version))
                download_filepath = local_zip_filepath
                # Try to download the resource
                print("-- Downloading " + url + " to: " + download_filepath + "...")
                self.logger.info("-- Downloading " + url + " to: " + download_filepath + "...")
                # Download the file to the downloads dir
                # Set the context for SSL (not checking!)
                context = ssl.SSLContext()
                with urllib.request.urlopen(url, context=context) as response, open(download_filepath , 'wb') as out_file:
                    shutil.copyfileobj(response, out_file)
                # Return success status
                return True
            except Exception as e:
                traceback.print_exc()
                return False

    # Get annualized zip file
    def download_annualized_zip_file(self, year):

        # Create the local .zip filepath for the year submitted
        local_zip_filepath = self.downloads_dirpath + self.local_cve_file.replace("{year}", str(year))
        # Check if file downloaded already
        if os.path.exists(local_zip_filepath):
            print("-- Using previously downloaded " + str(year) + " annualized CVE json resource...")
            self.logger.info("-- Using previously downloaded " + str(year) +  " annualized CVE json resource...")
            # Return success
            return True
        else:
            # Try to download the resource
            print("-- Downloading " + str(year) + " annualized CVE json resource...")
            self.logger.info("-- Downloading " + str(year) + " annualized CVE json resource...")
            try:
                url = self.nist_cve_json_url.replace("{year}", str(year))
                download_filepath = local_zip_filepath
                # Try to download the resource
                print("-- Downloading " + url + " to: " + download_filepath + "...")
                self.logger.info("-- Downloading " + url + " to: " + download_filepath + "...")
                # Download the file to the downloads dir
                # Set the context for SSL (not checking!)
                context = ssl.SSLContext()
                with urllib.request.urlopen(url, context=context) as response, open(download_filepath , 'wb') as out_file:
                    shutil.copyfileobj(response, out_file)

                # Check the file against hash
                if self.check_cve_download_hash(year): return True
                else: return False

            except Exception as e:
                traceback.print_exc()
                return False

    # Extract and insert all cpe_dict items in xml string
    def get_cpe_items_from_xml(self, cpe_file, cpe_version, xml):

        try:
            # Prepare the XML extraction
            root = etree.fromstring(xml)
            # Extract the cpe nodes
            for item in root.findall('.//{*}cpe-item'):
                cpe_item = {}
                # Append the filename
                cpe_item['file_name'] = cpe_file.rstrip(".zip")
                # Set the cpe_version
                cpe_item['cpe_version'] = cpe_version
                # Get CPE escaped string
                cpe_item['cpe_esc'] = item.attrib['name']
                #print("cpe_esc: " + cpe_esc)
                # Get product title
                product_elem = item.find('.//{*}title')
                cpe_item['title'] = product_elem.text
                ref_elem = item.find('.//{*}references')
                ref_arr = []
                try:
                    # Get reference list information
                    for ref in ref_elem.findall('.//{*}reference'):
                        url = ref.attrib['href']
                        type = ref.text
                        ref_arr.append({"url" : url, "type" : type})
                    cpe_item['ref_json'] = json.dumps(ref_arr)
                except: cpe_item['ref_json'] = None
                #print("ref_json: " + ref_json)
                # Get CPE 2.3 string
                if cpe_version == 2.3:
                    cpe_string_elem = item.find('.//{*}cpe23-item')
                    cpe_item['cpe_string'] = cpe_string_elem.attrib['name']
                    # nvd_id is not available in v2.3
                    cpe_item['nvd_id'] = None
                # Get CPE 2.2 string and nvd_id
                elif cpe_version == 2.2:
                    cpe_string_elem = item.find('.//{*}item-metadata')
                    # Only ASCII/URL encoded is available in v2.2
                    cpe_item['cpe_string'] = unquote(cpe_item['cpe_esc'])
                    cpe_item['nvd_id'] = cpe_string_elem.attrib['nvd-id']
                    print(cpe_item['nvd_id'])

                # Insert into database
                self.db_conn.insert_cpe_item(cpe_item)

        except Exception as e:
            traceback.print_exc()
            exit(0)


    # Delete the downloads
    def delete_unzipped_json(self, cve_filepath):
        # Remove .zip from filepath and delete
        cve_filepath = cve_filepath.replace(".zip", "")
        os.remove(cve_filepath)

    # Get updates from NIST and replace in database
    def update_cve_database(self):
        pass

    # Get updates from NIST and replace in database
    def update_cpe_database(self):
        pass

    # Check the downloaded CVE file for hash value
    def check_cve_download_hash(self, year):

        url = self.nist_cve_meta_url.replace("{year}", str(year))
        download_filepath = self.download_filepath + self.nist_cve_meta_url.split("/")[-1]
        # Try to download the metadata resource
        print("-- Downloading " + str(year) + " Metadata to: " + download_filepath + "...")
        self.logger.info("-- Downloading " + str(year) + " to: " + download_filepath + "...")
        # Download the file to the downloads dir
        # Set the context for SSL (not checking!)
        context = ssl.SSLContext()
        with urllib.request.urlopen(url, context=context) as response, open(download_filepath , 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        # Open the metadata file
        with open(download_filepath, "r") as infile:
            contents = infile.readlines()
        for line in contents:
            if line.startswith('sha256'):
                expected_sha256 = line.split(":")[-1]
        # Get the SHA256 hash of the file
        cve_file = self.download_filepath + self.local_cve_file.replace("{year}", str(year))
        with open(cve_file,"rb") as f:
            bytes = f.read()
            dl_sha256 = hashlib.sha256(bytes).hexdigest();
        print(expected_sha256)
        print(dl_sha256)
        if dl_sha256 == expected_sha256: return True
        else: return False
#
# Main function
if __name__ == "__main__":

    # Database args
    db_args = {
        "database_type" : "postgresql", # only postgresql available now
        "host" : "127.0.0.1",
        "port" : 5432, # PostgreSQL port
        "user" : "vuln_db",
        "passwd" : "Bg8G0X5CBNrIDyyH67wLK", # PostgreSQL password
        "db" : "vuln_db",
        "charset" : "utf8"
    }
    # Create instance
    importer = VulnDbPopulator(db_args)
    importer.populate()
