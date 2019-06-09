CREATE TABLE "logs" (
	"rule_name" character varying(32) NOT NULL,
	"bytes" bigint NOT NULL,
	"pkts" bigint NOT NULL,
	"hostname" character varying(16),
	"that_time" integer NOT NULL
);

REVOKE ALL on "logs" from PUBLIC;
GRANT ALL on "logs" to "postgres";
GRANT ALL on "logs" to "power";

CREATE  INDEX "logs_rule" on "logs" using btree ( "rule_name" "varchar_ops" );
CREATE UNIQUE INDEX "logs_rule_time" on "logs" using btree ( "rule_name" "varchar_ops", "that_time" "int4_ops" );
CREATE  INDEX "logs_time" on "logs" using btree ( "that_time" "int4_ops" );

