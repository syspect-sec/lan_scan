#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Alexa Check SQLProcessor
# Author: Joseph Lee
# Email: joseph@ripplesoftware.ca
# Website: www.ripplesoftware.ca
# Github: www.github.com/rippledj/alexa_check

import psycopg2
import traceback
import json
import LanScanLogger

class SQLProcess:

    # Initialize connection to database using arguments
    def __init__(self, db_args):

        # Pass the database type to class variable
        self.database_type = db_args['database_type']

        # Define class variables
        self._host = db_args['host']
        self._port = db_args['port']
        self._username = db_args['user']
        self._password = db_args['passwd']
        self._dbname = db_args['db']
        self._charset = db_args['charset']
        self._conn = None
        self._cursor = None

    # Establish connection to the database
    def connect(self):

        logger = LanScanLogger.logging.getLogger("LanScan_Logs")

        # Connect to PostgreSQL
        if self.database_type == "postgresql":

            if self._conn == None:
                try:
                    # Get a connection, if a connect cannot be made an exception will be raised here
                    self._conn = psycopg2.connect("host=" + self._host +  " dbname=" + self._dbname + " user=" + self._username + " password=" + self._password + " port=" + str(self._port))
                    self._conn.autocommit = True
                except Exception as e:
                    return False

            if self._cursor == None:
                try:
                    # conn.cursor will return a cursor object, you can use this cursor to perform queries
                    self._cursor = self._conn.cursor()
                    print("Connection to PostgreSQL database established.")
                    logger.info("Connection to PostgreSQL database established.")
                except Exception as e:
                    return False

            # Return success status for connection
            return True

    # Check for each required table
    def check_database_installed(self, required_tables):

        logger = LanScanLogger.logging.getLogger("LanScan_Logs")

        # Get list of all tables in the vuln_db database
        sql = """SELECT tablename
        FROM pg_catalog.pg_tables
        WHERE schemaname = 'vuln_db'"""
        self._cursor.execute(sql)
        installed = self._cursor.fetchall()

        # Print check
        for row in installed:
            if row[0] in required_tables:
                i = required_tables.index(row[0])
                required_tables.pop(i)
        if len(required_tables) == 0: return True
        else: return False

    # Check that each table in vuln_db is populated
    def check_database_populated(self, required_tables):

        logger = LanScanLogger.logging.getLogger("LanScan_Logs")

        try:
            for table in required_tables:
                print("** Checking " + table + " is populated...")
                # Get list of all tables in the vuln_db database
                sql = """SELECT count(*)
                FROM """ + table
                self._cursor.execute(sql)
                count = self._cursor.fetchone()
                print(count)
                if count[0] == 0:
                    print("-- Table" + table + " is not populated...")
                    return False
        except Exception as e:
            traceback.print_exc()
            exit(0)
        # All tables have data then return True
        return True

    # Inserts CPE item into database
    def insert_cpe_item(self, cpe_item):

        # Import logger
        logger = LanScanLogger.logging.getLogger("LanScan_Logs")

        print("-- Inserting " + cpe_item['cpe_esc'] + "...")

        try:
            sql = """INSERT INTO vuln_db.cpe_dictionary
            (cpe_version, cpe_esc, title, reference_json, cpe_string, file_name)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            values = (
                cpe_item['cpe_version'],
                cpe_item["cpe_esc"],
                cpe_item['title'],
                cpe_item['ref_json'],
                cpe_item['cpe_string'],
                cpe_item['file_name']
            )
            self._cursor.execute(sql, values)

        except Exception as e:
            traceback.print_exc()
            logger.error("-- Failed to insert CVE item " + cpe_item['cpe_23'] +  " into database...")
            logger.error(traceback.format_exc())

    # Insert a single item from CVE json file
    def insert_cve_item(self, cve_item):

        # Import logger
        logger = LanScanLogger.logging.getLogger("LanScan_Logs")

        try:
            sql = """INSERT INTO vuln_db.nist_cve
            (data_version, cve_id, assigner, problem_types, info_references,
            decriptions, cpe_23_uri_nodes, v3_cvss_version, v3_vector_string, v3_attack_vector,
            v3_attack_complexity, v3_privileges_required, v3_user_interaction, v3_scope, v3_confidentiality_impact,
            v3_integrity_impact, v3_availability_impact, v3_base_score, v3_base_severity, v3_exploitability_score,
            v3_impact_score, v2_cvss_version, v2_vector_string, v2_access_vector, v2_access_complexity,
            v2_authentication, v2_confidentiality_impact, v2_integrity_impact, v2_availability_impact, v2_base_score,
            v2_severity, v2_exploitability_score, v2_impact_score, v2_ac_insufficient_info, v2_obtain_all_privilege,
            v2_obtain_user_privilege, v2_obtain_other_privilege, v2_user_interaction_required, file_name)
            VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                cve_item['data_version'],
                cve_item['cve_id'],
                cve_item['assigner'],
                cve_item['problem_types'],
                cve_item['info_references'],
                cve_item['descriptions'],
                cve_item['cpe_23_uri_nodes'],
                cve_item['v3_cvss_version'],
                cve_item['v3_vector_string'],
                cve_item['v3_attack_vector'],

                cve_item['v3_attack_complexity'],
                cve_item['v3_privileges_required'],
                cve_item['v3_user_interaction'],
                cve_item['v3_scope'],
                cve_item['v3_confidentiality_impact'],
                cve_item['v3_integrity_impact'],
                cve_item['v3_availability_impact'],
                cve_item['v3_base_score'],
                cve_item['v3_base_severity'],
                cve_item['v3_exploitability_score'],

                cve_item['v3_impact_score'],
                cve_item['v2_cvss_version'],
                cve_item['v2_vector_string'],
                cve_item['v2_access_vector'],
                cve_item['v2_access_complexity'],
                cve_item['v2_authentication'],
                cve_item['v2_confidentiality_impact'],
                cve_item['v2_integrity_impact'],
                cve_item['v2_availability_impact'],
                cve_item['v2_base_score'],

                cve_item['v2_severity'],
                cve_item['v2_exploitability_score'],
                cve_item['v2_impact_score'],
                cve_item['v2_ac_insufficient_info'],
                cve_item['v2_obtain_all_privilege'],
                cve_item['v2_obtain_user_privilege'],
                cve_item['v2_obtain_other_privilege'],
                cve_item['v2_user_interaction_required'],
                cve_item['file_name']
            )
            self._cursor.execute(sql, values)

        except Exception as e:
            traceback.print_exc()
            logger.error("-- Failed to insert CVE item " + cve_item['cve_id'] +  " into database...")
            logger.error(traceback.format_exc())
