-- MySQL dump 9.11
--
-- Host: localhost    Database: ipac
-- ------------------------------------------------------
-- Server version	4.0.20-standard-log

--
-- Table structure for table `logs`
--

CREATE TABLE logs (
  that_time bigint(20) NOT NULL default '0',
  rule_name varchar(128) NOT NULL default '',
  bytes bigint(20) default NULL,
  pkts bigint(20) default NULL,
  hostname varchar(64) default NULL,
  PRIMARY KEY  (that_time,rule_name)
) TYPE=MyISAM;


