/*
 *
 * $Id: mysql.c,v 1.4 2004/09/26 16:16:30 friedl Exp $
 *
 * mysql backend to ipac-ng
 * Copyright (C) 2001-2003 Al Zakharov, 2003-2004 Friedrich Lobenstock, 
 *               2004 Simon Hausman, 2004 Denis O.Philippov
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
#include "mysql_backend.h"
#include "../sharedsql/sharedsql.h"
#include <mysql/mysql.h>

static MYSQL conn;

static MYSQL_RES *res = NULL;

static int mysql_stor_open (int flag);

static void sql_close_connection ();

static const storage_method_t interface_entry = {
	"mysql",
	mysql_stor_open,
	sql_stor_store_record,
	sql_stor_list_timestamps,
	sql_stor_get_records,
	sql_stor_get_summary,
	sql_stor_delete_record,
	sql_stor_close
};

const storage_method_t *ipac_sm_interface_mysql () {
	return &interface_entry;
}

/* include shared sql routines */
#include "../sharedsql/sharedsql.c"

static int mysql_stor_open (int flag)
{
	sql_stor_open();
	mysql_init(&conn);
	if (!dbport) dbport="0";
	if ( !mysql_real_connect(&conn, dbhost, dbuser, dbpass, dbname,
			atoi(dbport), NULL, 0) ) {
		fprintf(stderr, "Connection to database '%s' failed.\n", dbname);
		fprintf(stderr, "%s\n", mysql_error(&conn));
		mysql_close(&conn);
		DPRINTF ("failed mysql_stor_open\n");
		return -1;
	}

	DPRINTF("mysql_stor_open\n");
	storage_opened = 1;
	return 0;
}

static int sql_execute_query (const char *query)
{
	DPRINTF ("%s\n", query);
	if (mysql_query (&conn, query) || 
	   (((res = mysql_store_result(&conn)) == NULL) && (mysql_errno(&conn) > 0 ))) {
		fprintf (stderr, "%s : SQL command (%s) failed\nError: %s\n", 
			me, query, mysql_error(&conn));
		DPRINTF ("failed: %s\n", mysql_error(&conn));
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
	if (res) {
		mysql_free_result (res);
		res = NULL;
	}
}

static int sql_number_of_affected_rows ()
{
	return mysql_affected_rows (&conn);
}

static const char *sql_result_get_value (int row, int column)
{
	MYSQL_ROW rw;
	mysql_data_seek(res, row);

	if ((rw = mysql_fetch_row(res))) {
		return rw[column];
	}
	return NULL;
}

static void sql_close_connection()
{
	mysql_close(&conn);
}

