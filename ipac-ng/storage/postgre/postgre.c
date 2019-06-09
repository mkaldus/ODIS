/*
 *
 * $Id: postgre.c,v 1.31 2004/06/13 01:14:30 friedl Exp $
 *
 * postgresql backend to ipac-ng
 * Copyright (C) 2001-2003 Al Zakharov, 2003-2004 Friedrich Lobenstock, 2004 Simon Hausman
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * The author can be reached via email: kaiser13@mail2000.ru, or by 
 * fido: Al_Zaharov@p88.f58.n5005.z2.fidonet.org
 *
*/

#include "ipac.h"
#include "postgre.h"
#include "../sharedsql/sharedsql.h"
#include <libpq-fe.h>

static char *pgoptions = NULL;
static char *pgtty = NULL;

static PGconn *conn;
static PGresult *res;

static int postgre_stor_open (int flag);

static void sql_close_connection ();

static const storage_method_t interface_entry = {
	"postgre",
	postgre_stor_open,
	sql_stor_store_record,
	sql_stor_list_timestamps,
	sql_stor_get_records,
	sql_stor_get_summary,
	sql_stor_delete_record,
	sql_stor_close
};

const storage_method_t *ipac_sm_interface_postgre () {
	return &interface_entry;
}

/* include shared sql routines */
#include "../sharedsql/sharedsql.c"

static int postgre_stor_open (int flag)
{
	sql_stor_open();

	conn = PQsetdbLogin (dbhost, dbport, pgoptions, pgtty, dbname, dbuser,
									dbpass);
	if (PQstatus (conn) == CONNECTION_BAD) {
		fprintf (stderr, "Connection to database '%s' failed.\n", dbname);
		fprintf (stderr, "%s", PQerrorMessage (conn));

		DPRINTF ("failed postgre_stor_open\n");

		PQfinish (conn);
		return -1;
	}

	DPRINTF ("postgre_stor_open\n");
	storage_opened = 1;
	return 0;
}

static int sql_execute_query (const char *query)
{
	DPRINTF ("%s\n", query);
	res = PQexec (conn, query);
	if (!res || (PQresultStatus (res) != PGRES_COMMAND_OK && PQresultStatus (res) != PGRES_TUPLES_OK)) {
		fprintf (stderr, "%s : SQL command (%s) failed\nError: %s\n", me, query, PQresultErrorMessage (res));
		DPRINTF ("failed: %s\n", PQresultErrorMessage (res));
		sql_clear_result();
		return -1;
	}
	return 0;
}

static int sql_execute_simple_query (const char *query)
{
	int resultCode;
	
	resultCode = sql_execute_query (query);
	if (resultCode >= 0)
		sql_clear_result();
	return resultCode;
}

static void sql_clear_result()
{
	PQclear (res);
}

static int sql_number_of_affected_rows ()
{
	return PQntuples (res);
}

static const char *sql_result_get_value (int row, int column)
{
	return PQgetvalue (res, row, column);
}

static void sql_close_connection()
{
	PQfinish (conn);
}

