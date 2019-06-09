
-- the drop table has been commented out to protect the innocent ;-)
-- DROP TABLE logs;


--
-- Please increase the size of the hostname field if the output of
--
--   hostname | wc -c
--
-- returns a number greater than 16.
--


CREATE TABLE "logs" (
	"rule_name" character varying(32) NOT NULL,
	"bytes" bigint NOT NULL,
	"pkts" bigint NOT NULL,
	"hostname" character varying(16),
	"that_time" integer NOT NULL
);

REVOKE ALL on "logs" from PUBLIC;
GRANT ALL on "logs" to "postgres";
GRANT ALL on "logs" to "ipac";

CREATE  INDEX "logs_rule" on "logs" using btree ( "rule_name" "varchar_ops" );
CREATE UNIQUE INDEX "logs_rule_time" on "logs" using btree ( "rule_name" "varchar_ops", "that_time" "int4_ops" );
CREATE  INDEX "logs_time" on "logs" using btree ( "that_time" "int4_ops" );

