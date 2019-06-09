/*
 *
 * $Id: sqlite.c,v 1.3 2004/06/14 23:25:27 friedl Exp $
 *
 * sqlite backend to ipac-ng Copyright (C) 2001-2004 Al Zakharov, 2004 Simon Hausmann
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
*/

#include "ipac.h"
#include "../sharedsql/sharedsql.h"
#include <sqlite.h>
#include <unistd.h>
#include <string.h>

static sqlite *conn;
static char **res;
static int nRows;
static int nCols;
static char *err;

static int sqlite_stor_open (int flag);

static void sql_close_connection ();

static const storage_method_t interface_entry = {
	"sqlite",
	sqlite_stor_open,
	sql_stor_store_record,
	sql_stor_list_timestamps,
	sql_stor_get_records,
	sql_stor_get_summary,
	sql_stor_delete_record,
	sql_stor_close
};

const storage_method_t *ipac_sm_interface_sqlite () {
	return &interface_entry;
}

static int sqlite_stor_open (int flag);
static int sql_execute_query (const char *query);
static int sql_execute_simple_query (const char *query);
static void sql_clear_result();
static int sql_number_of_affected_rows ();
static const char *sql_result_get_value (int row, int column);
static void sql_close_connection();

/* include shared sql routines */
#include "../sharedsql/sharedsql.c"

static int sqlite_stor_open (int flag)
{
	char filename[256];
	
	sql_stor_open();

	/* open database filename as sql database name plus suffix ".db" in 
	   the ipac datadir so the database file ends up at the same place 
	   all the time */
        conn = sqlite_open (strcat (strcat (strcat (
        	strcpy (filename, datadir), "/"), dbname), ".db"), 0, &err);
	if (err) {
    		fprintf (stderr, "Connection to database '%s' failed.\n", filename);
    		fprintf (stderr, "Error: %s\n", err);
    		sqlite_freemem (err);
    		return 1;
	}

	if (sqlite_get_table (conn, "select name from sqlite_master where type='table' and name='logs'", 
			      &res, &nRows, &nCols, 0) != SQLITE_OK || nRows != 1) {
		fprintf (stderr, "ipac-ng[sqlite]: creating logs table\n");

		sqlite_exec (conn, "CREATE TABLE logs ("
				"rule_name character varying(64) NOT NULL,"
				"bytes bigint NOT NULL,"
				"pkts bigint NOT NULL,"
				"that_time bigint NOT NULL,"
				"hostname character varying(256)"
				")", 0, 0, 0);
	}

	storage_opened = 1;
	return 0;
}

static int sql_execute_query (const char *query)
{
	DPRINTF ("%s\n", query);
	int resultCode = sqlite_get_table (conn, query, &res, &nRows, &nCols, &err);
	if (resultCode != SQLITE_OK) {
		fprintf (stderr, "%s : SQL command (%s) failed\nError: %s\n", me, query, err);
		DPRINTF ("failed: %s\n", err);
		sql_clear_result();
		return -1;
	}
	return 0;
}

static int sql_execute_simple_query (const char *query)
{
	DPRINTF ("%s\n", query);
	if (sqlite_exec (conn, query, 0, 0, 0) != SQLITE_OK) {
		DPRINTF ("failed: %s\n", err);
		return -1;
	}
	return 0;
}

static void sql_clear_result()
{
	sqlite_free_table (res);
}

static int sql_number_of_affected_rows ()
{
	return nRows;
}

static const char *sql_result_get_value (int row, int column)
{
	/* + 1 because the first row contains the headers */
	return res[((row + 1) * nCols) + column];
}

static void sql_close_connection()
{
	sqlite_close (conn);
}

