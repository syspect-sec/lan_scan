-- LanScan.py Database Initialization
-- Ripple Software Consulting
-- Author: Joseph Lee
-- Email: joseph@ripplesoftware.ca
-- Description:
-- Run this file in PostgreSQL before running vulnerability check
--$ psql -U postgres -d postgres -f postgres_setup.sql

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

-- -----------------------------------------------------
-- Create Databse vuln_db
-- -----------------------------------------------------

DROP DATABASE IF EXISTS vuln_db;
CREATE DATABASE vuln_db;

\c vuln_db;

DROP SCHEMA IF EXISTS vuln_db CASCADE;
CREATE SCHEMA IF NOT EXISTS vuln_db;

-- -----------------------------------------------------
-- Create Agency Tables
-- -----------------------------------------------------

-- CPE Dictionary
-- https://nvd.nist.gov/products/cpe
CREATE TABLE vuln_db.cpe_dictionary (
  cpe_version real,
  cpe_esc text,
  title text,
  reference_json json,
  cpe_string text,
  nvd_id int,
  file_name character varying(50)
);

--
-- Add comments to all columns
--
comment on column vuln_db.cpe_dictionary.cpe_esc is 'The ASCII escaped CPE string for the product';
comment on column vuln_db.cpe_dictionary.title is 'The product title';
comment on column vuln_db.cpe_dictionary.reference_json is 'references with url and type (i.e.: advisory, product description, etc.)';
comment on column vuln_db.cpe_dictionary.cpe_string is 'The CPE string for the product';
comment on column vuln_db.cpe_dictionary.file_name is 'The source CPE dictionary filename';


-- NIST CPE to CPE Concordance
-- https://nvd.nist.gov/vuln/data-feeds
CREATE TABLE vuln_db.nist_cve (
  data_version real,
  cve_id character varying(20),
  assigner text,
  problem_types text[],
  info_references json,
  decriptions text[],
  cpe_23_uri_nodes json,
  v3_cvss_version real,
  v3_vector_string character varying(50),
  v3_attack_vector character varying(25),
  v3_attack_complexity character varying(10),
  v3_privileges_required character varying(10),
  v3_user_interaction character varying(10),
  v3_scope character varying(25),
  v3_confidentiality_impact character varying(10),
  v3_integrity_impact character varying(10),
  v3_availability_impact character varying(10),
  v3_base_score real,
  v3_base_severity character varying(25),
  v3_exploitability_score real,
  v3_impact_score real,
  v2_cvss_version real,
  v2_vector_string character varying(50),
  v2_access_vector character varying(25),
  v2_access_complexity character varying(10),
  v2_authentication character varying(25),
  v2_confidentiality_impact character varying(10),
  v2_integrity_impact character varying(10),
  v2_availability_impact character varying(10),
  v2_base_score real,
  v2_severity character varying(25),
  v2_exploitability_score real,
  v2_impact_score real,
  v2_ac_insufficient_info boolean,
  v2_obtain_all_privilege boolean,
  v2_obtain_user_privilege boolean,
  v2_obtain_other_privilege boolean,
  v2_user_interaction_required boolean,
  file_name character varying(50)
);

--
-- Add comments to all columns
--
comment on column vuln_db.nist_cve.data_version is '';
comment on column vuln_db.nist_cve.cve_id is '';
comment on column vuln_db.nist_cve.assigner is '';
comment on column vuln_db.nist_cve.problem_types is '';
comment on column vuln_db.nist_cve.info_references is '';
comment on column vuln_db.nist_cve.decriptions is '';
comment on column vuln_db.nist_cve.cpe_23_uri_nodes is '';
comment on column vuln_db.nist_cve.v3_cvss_version is '';
comment on column vuln_db.nist_cve.v3_vector_string is '';
comment on column vuln_db.nist_cve.v3_attack_vector is '';
comment on column vuln_db.nist_cve.v3_attack_complexity is '';
comment on column vuln_db.nist_cve.v3_privileges_required is '';
comment on column vuln_db.nist_cve.v3_user_interaction is '';
comment on column vuln_db.nist_cve.v3_scope is '';
comment on column vuln_db.nist_cve.v3_confidentiality_impact is '';
comment on column vuln_db.nist_cve.v3_integrity_impact is '';
comment on column vuln_db.nist_cve.v3_availability_impact is '';
comment on column vuln_db.nist_cve.v3_base_score is '';
comment on column vuln_db.nist_cve.v3_base_severity is '';
comment on column vuln_db.nist_cve.v3_exploitability_score is '';
comment on column vuln_db.nist_cve.v3_impact_score is '';
comment on column vuln_db.nist_cve.v2_cvss_version is '';
comment on column vuln_db.nist_cve.v2_vector_string is '';
comment on column vuln_db.nist_cve.v2_access_vector is '';
comment on column vuln_db.nist_cve.v2_access_complexity is '';
comment on column vuln_db.nist_cve.v2_authentication is '';
comment on column vuln_db.nist_cve.v2_confidentiality_impact is '';
comment on column vuln_db.nist_cve.v2_integrity_impact is '';
comment on column vuln_db.nist_cve.v2_availability_impact is '';
comment on column vuln_db.nist_cve.v2_base_score is '';
comment on column vuln_db.nist_cve.v2_severity is '';
comment on column vuln_db.nist_cve.v2_exploitability_score is '';
comment on column vuln_db.nist_cve.v2_impact_score is '';
comment on column vuln_db.nist_cve.v2_ac_insufficient_info is '';
comment on column vuln_db.nist_cve.v2_obtain_all_privilege is '';
comment on column vuln_db.nist_cve.v2_obtain_user_privilege is '';
comment on column vuln_db.nist_cve.v2_obtain_other_privilege  is '';
comment on column vuln_db.nist_cve.v2_user_interaction_required is '';
comment on column vuln_db.nist_cve.file_name is 'The name of the source file with .zip extension removed';

-- -----------------------------------------------------
-- Create PostgreSQL Users
-- -----------------------------------------------------

-- Drop user if exists and create a new user with password
DROP USER IF EXISTS vuln_db;
CREATE USER vuln_db LOGIN PASSWORD 'Bg8G0X5CBNrIDyyH67wLK';
ALTER USER vuln_db WITH SUPERUSER;

-- Change the owner of uspto database to vuln_db user
ALTER DATABASE vuln_db OWNER TO vuln_db;
ALTER SCHEMA vuln_db OWNER to vuln_db;
ALTER DATABASE vuln_db SET search_path TO vuln_db;

-- Grant privileges to all corresponding databases
GRANT USAGE ON SCHEMA vuln_db TO vuln_db;
GRANT ALL ON ALL TABLES IN SCHEMA vuln_db TO vuln_db;
