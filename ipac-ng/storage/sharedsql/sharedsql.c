/*
 *
 * $Id: sharedsql.c,v 1.2 2004/08/24 18:38:58 friedl Exp $
 *
 * generic functions equal for all sql backends
 * Copyright (C) 2001-2003 Al Zakharov, 2003-2004 Friedrich Lobenstock, 2004 Simon Hausmann
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
*/

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/param.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>

extern char *ahost;

/* the statical variables used for returning results */
static data_record_type  *_timestamp_lst = NULL;
static int               _timestamp_max  = 0;
static rule_type         *_rules_lst     = NULL;
static int               _rules_max      = 0;

#ifdef DEBUG_DB
static int fd = 0;
#endif

/* a safety margin of 0.5 percent for memory allocations */
#define MEMORY_SAFETY_MARGIN(x) (int)(x * 0.005 + 0.5)

static void sql_stor_open ()
{
#ifdef DEBUG_DB
	char *log_file;

	// construct the name of the logfile
	log_file = xmalloc(strlen(datadir) + sizeof(DEBUG_DB_LOGFILE) + 2);
	sprintf(log_file, "%s/" DEBUG_DB_LOGFILE, datadir);

	// open the logfile for appending
	fd = open (log_file, O_CREAT|O_WRONLY|O_APPEND|O_SYNC);
#endif	
}

static int sql_stor_store_record (const data_record_type *data)
{
	rule_type *rule, *firstrule;
	char wh_exec[380];

	firstrule = data->firstrule;

	if (firstrule == NULL)
		return 0;

	/*
	DPRINTF ("BEGIN\n");
	if (sql_execute_simple_query ("BEGIN"))
	    return 1;
	*/
	
	for (rule = firstrule; rule; rule = rule->next) {
		sprintf (wh_exec, "INSERT INTO logs (rule_name, bytes, pkts, that_time, hostname) "
				"VALUES ('%s', '%llu', '%llu', '%lu', '%s')", 
				rule->name, rule->bytes, rule->pkts, data->timestamp, hostname);

		DPRINTF ("sql_stor_store_record\n");

		/* FIXME: we don't report back error's for now 
		   actually we accept that single entries might fail, eg. they are double, but
		   that's why we have uniq indices :-) */
		sql_execute_simple_query (wh_exec);
	}

	/*
	DPRINTF ("COMMIT\n");
	return sql_execute_simple_query ("COMMIT");
	*/
	return 0;
}

static int sql_stor_list_timestamps (timestamp_t start, timestamp_t end,
		timestamp_t **data, timestamp_t *just_before,
		timestamp_t *just_after, char *ahost)
{
	int i;	
	timestamp_t *ts_list = NULL;
	int ts_list_len = 0;
	char wh_exec[250];

	DPRINTF ("sql_stor_list_timestamps (%lu, %lu, **data, %s, %s, %s)\n", 
		start, end, (just_before!=NULL) ? "*just_before" : "NULL", 
		(just_after!=NULL) ? "*just_after" : "NULL", (ahost!=NULL) ? ahost : "NULL");

	sprintf (wh_exec, "SELECT distinct that_time FROM logs WHERE ");
	if (ahost)
		sprintf (wh_exec+strlen (wh_exec), "hostname = '%s' AND ", ahost);
	sprintf (wh_exec+strlen (wh_exec), "that_time between %lu and %lu "
		"ORDER BY that_time ASC", start, end);

	if (sql_execute_query (wh_exec)) {
		return -1;
	}
	ts_list_len = sql_number_of_affected_rows ();

	if (ts_list_len > 0) {
		ts_list = xmalloc (ts_list_len * sizeof (timestamp_t));
		for (i = 0; i < ts_list_len; i++)
			ts_list[i] = strtoul (sql_result_get_value (i, 0), NULL, 10);
		sql_clear_result();

		if (just_before != NULL) {
			sprintf (wh_exec, "SELECT that_time FROM logs WHERE "
					"that_time < %lu ORDER BY that_time DESC LIMIT 1", start);

			if (sql_execute_query (wh_exec)) {
				free (ts_list);
				return -1;
			}
			if (sql_number_of_affected_rows () > 0)
				*just_before = strtoul (sql_result_get_value (0, 0), NULL, 10);
			else
				*just_before = (timestamp_t) -1 ;
			sql_clear_result ();
		}

		if (just_after != NULL) {
			sprintf (wh_exec, "SELECT that_time FROM logs WHERE "
					"that_time > %lu ORDER BY that_time ASC LIMIT 1", end);

			if (sql_execute_query (wh_exec)) {
				free (ts_list);
				return -1;
			}
			if (sql_number_of_affected_rows () > 0)
				*just_after = strtoul (sql_result_get_value (0, 0), NULL, 10);
			else
				*just_after = (timestamp_t) -1;
			sql_clear_result();
		}

		*data = ts_list;

	}

	DPRINTF ("sql_stor_list_timestamps returning: %i\n", ts_list_len);
	return ts_list_len;
}

static int sql_stor_get_records (timestamp_t timestamp_b, timestamp_t timestamp_e, 
		data_record_type **data, char *filter)
{
	rule_type *r, *r1 = NULL, *rules;
	int i, nr_timestamps, index, nr_rules;
	timestamp_t timestamp_akt;
	char wh_exec[320];
	/* char *tmp; */

	DPRINTF ("sql_stor_get_records (%lu, %lu, **data, %s)\n", 
		timestamp_b, timestamp_e, (filter!=NULL) ? filter : "NULL");

	if (timestamp_e) {
		sprintf (wh_exec, "SELECT COUNT(distinct that_time) FROM logs WHERE ");
		if (ahost)
			sprintf (wh_exec+strlen (wh_exec), "hostname = '%s' AND ", ahost);
		sprintf (wh_exec+strlen (wh_exec), "that_time between '%lu' and '%lu'", 
						 timestamp_b, timestamp_e);
		if (filter)
			sprintf (wh_exec+strlen (wh_exec), " AND rule_name like '%%%s%%'", 
							filter);

		if (sql_execute_query (wh_exec)) {
			sql_close_connection ();
			exit (-1);
		}
		nr_timestamps = strtol (sql_result_get_value (0,0), NULL, 10);
		DPRINTF ("result: %u timestamps\n", nr_timestamps);
		sql_clear_result();
	} else {
		nr_timestamps = 1;
		DPRINTF ("searching for exactly one timestamp: %u\n", timestamp_b);
	}
	
	sprintf (wh_exec, "SELECT rule_name, bytes, pkts, that_time, hostname FROM logs WHERE ");
	if (ahost)
		sprintf (wh_exec+strlen (wh_exec), "hostname = '%s' AND ", ahost);
	if (timestamp_e) {
		sprintf (wh_exec+strlen (wh_exec), "that_time between '%lu' and '%lu'",
						timestamp_b, timestamp_e);
	} else {
		sprintf (wh_exec+strlen (wh_exec), "that_time = '%lu'", timestamp_b);
	}
	if (filter)
		sprintf (wh_exec+strlen (wh_exec), " AND rule_name like '%%%s%%'", filter);
	if (timestamp_e)
		sprintf (wh_exec+strlen (wh_exec), " ORDER BY that_time");

	if (sql_execute_query (wh_exec)) {
		sql_close_connection ();
		exit (-1);
	}
	nr_rules = sql_number_of_affected_rows ();
	DPRINTF ("result: %u data records\n", nr_rules);

	DPRINTF ("starting to convert data into our format\n");

	/* create record_data_type. */
	if (nr_timestamps > _timestamp_max) {
		/* need to increase size of data_record_type array */

		if (_timestamp_lst != NULL) {
			/* as realloc does not support a count parameter we free the old list first 
			   and then call calloc again */
			DPRINTF ("freeing memory of old timestamp list of size %i\n", _timestamp_max);
			free (_timestamp_lst);
		}

		/* always add a safety margin */
		_timestamp_max = nr_timestamps + MEMORY_SAFETY_MARGIN(nr_timestamps);

		DPRINTF ("allocating memory for timestamp list with %i elements\n", _timestamp_max);
		DPRINTF ("  calloc (cnt %i, size %u) = %lu bytes\n", _timestamp_max, sizeof (data_record_type), (long)((long)_timestamp_max * (long)sizeof (data_record_type)));
		_timestamp_lst = (data_record_type *)calloc (_timestamp_max, sizeof (data_record_type));
	
		if (_timestamp_lst == NULL) {
			fprintf (stderr,"%s: data_record_type calloc(cnt %i, size %u) failed: %s\n", me, _timestamp_max, sizeof (data_record_type), strerror(errno));

			DPRINTF ("failed: %s\n", strerror(errno));

			sql_clear_result ();
			sql_close_connection ();
			exit (-1);
		}
	}
	*data = _timestamp_lst;

	/* create rule_type. */
	if (nr_rules > _rules_max) {
		/* need to increase size of rule_type array */
		
		if (_rules_lst != NULL) {
			/* as realloc does not support a count parameter we free the old list first 
			   and then call calloc again */
			DPRINTF ("freeing memory of old timestamp list of size %i\n", _rules_max);
			free (_rules_lst);
		}

		/* always add a safety margin */
		_rules_max = nr_rules + MEMORY_SAFETY_MARGIN(nr_rules);

		DPRINTF ("allocating memory for rule list with %i elements\n", _rules_max);
		DPRINTF ("  calloc (cnt %i, size %u) = %lu bytes\n", _rules_max, sizeof (rule_type), (long)((long)_rules_max * (long)sizeof (rule_type)));
		_rules_lst = (rule_type *)calloc (_rules_max, sizeof (rule_type));
	
		if (_rules_lst == NULL) {
			fprintf (stderr,"%s: rule_type calloc(cnt %i, size %u) failed: %s\n", me, _rules_max, sizeof (rule_type), strerror(errno));

			DPRINTF ("failed: %s\n", strerror(errno));

			sql_clear_result ();
			sql_close_connection ();
			exit (-1);
		}
	}
	rules = _rules_lst;

	index = -1;
	timestamp_akt = 0;
	for (i = 0; i < nr_rules; i++) {
		// currently timestamp_t is of type time_t which is essentially long
		timestamp_t tstamp_new = strtol ((char *) sql_result_get_value (i,3), NULL, 10);
		if (tstamp_new != timestamp_akt) { // do we have a new timestamp?
			timestamp_akt = tstamp_new;
			index++;
			if (index > nr_timestamps) {
				fprintf (stderr,"%s: We got more records than timestamps "
					"were reported before. This should not happen!\n", me);

				DPRINTF ("We got more records than timestamps "
					"were reported before. This should not happen!\n");

				sql_clear_result ();
				sql_close_connection ();
				exit (-1);
			}
			(*data)[index].timestamp = timestamp_akt;
			/* FIXME: Two records with the same 'that_time' field but different 
			          hostname fields get listed as being from the hostname of 
			          the first record. Therefore it makes no sense and is plain 
			          wrong to store the hostname in this query. */
			
			/* tmp = (char *)PQgetvalue (res, i, 4);
			(*data)[index].machine_name = calloc(1, strlen(tmp)+1);
			
			if ((*data)[index].machine_name == NULL) {
				fprintf (stderr,"%s: calloc(1, size %u) for string \"%s\" failed: %s\n", me, strlen(tmp)+1, tmp, strerror(errno));

				DPRINTF ("calloc(1, size %u) for string \"%s\" failed: %s\n", strlen(tmp)+1, tmp, strerror(errno));

				sql_clear_result ();
				sql_close_connection ();
				exit (-1);
			}
			memcpy((*data)[index].machine_name, tmp, strlen(tmp)+1); */
			(*data)[index].machine_name = NULL;
			
			(*data)[index].firstrule = NULL;
			r1 = NULL;
		}

		r = &rules[i];
		r->next = NULL;

		if (r1 == NULL)
			 (*data)[index].firstrule = r;
		else
			r1->next = r;
		r1 = r;

		// never copy more than MAX_RULE_NAME_LENGTH+1 bytes from the resulting rule name
		strncpy (r->name, (char *) sql_result_get_value (i, 0), MAX_RULE_NAME_LENGTH+1);
		// make sure it's a null terminated string
		r->name[MAX_RULE_NAME_LENGTH] = '\0';
		r->bytes = strtoull (sql_result_get_value (i, 1), NULL, 10);
		r->pkts = strtoull (sql_result_get_value (i, 2), NULL, 10);

#ifdef DEBUG_DB_LEVEL2
		DPRINTF ("Record: %s, bytes %llu, pkts %llu\n", r->name, r->bytes, r->pkts);
#endif	
	}
	sql_clear_result ();

	DPRINTF ("data conversion finished\n");
	DPRINTF ("sql_stor_get_records returning: %i\n", index+1);
	return index+1;
}

static int sql_stor_get_summary (timestamp_t timestamp_b, timestamp_t timestamp_e, 
		data_record_type **data, char *filter)
{
	rule_type *r, *r1 = NULL;
	int i, nr_timestamps = 0, index;
	timestamp_t timestamp_akt;
	char wh_exec[320];

	DPRINTF ("sql_stor_get_summary (%lu, %lu, **data, %s)\n", 
		timestamp_b, timestamp_e, (filter!=NULL) ? filter : "NULL");

	if (!timestamp_e) 
		timestamp_e = timestamp_b;

	if (ahost)
		sprintf (wh_exec, "SELECT rule_name, sum(bytes), sum(pkts), hostname FROM logs "
			"WHERE "
			"hostname = '%s' and that_time between '%lu' and '%lu' ",
			 ahost, timestamp_b, timestamp_e);
	else
		sprintf (wh_exec, "SELECT rule_name, sum(bytes), sum(pkts), hostname FROM logs "
				"WHERE "
				"that_time between '%lu' and '%lu' ",
				timestamp_b, timestamp_e);
	if (filter)
		sprintf (wh_exec+strlen (wh_exec), " and rule_name like '%%%s%%'", filter);

	sprintf (wh_exec+strlen (wh_exec), " group by rule_name, hostname");

	if (sql_execute_query (wh_exec)) {
		sql_close_connection ();
		exit (-1);
	}

	DPRINTF ("starting to convert data into our format\n");

	/* create record_data_type. */
	*data = (data_record_type *)xmalloc (sizeof (data_record_type));

	index = -1;
	timestamp_akt = 0;
	for (i = 0; i < sql_number_of_affected_rows (); i++) {
		timestamp_t tstamp_new = timestamp_b; 
		if (tstamp_new != timestamp_akt) { // do we have a new timestamp?
			timestamp_akt = tstamp_new;
			index++;
			if (index > nr_timestamps) {
				fprintf (stderr,"We got more records then timestamps "
					"were reported before. This should not happen\n");

				DPRINTF ("We got more records then timestamps "
					"were reported before. This should not happen\n");

				sql_clear_result ();
				sql_close_connection ();
				exit (-1);
			}
			(*data)[index].timestamp = timestamp_akt;

			/* FIXME: Two records with the same 'that_time' field but different 
			          hostname fields get listed as being from the hostname of 
			          the first record. Therefore it makes no sense and is plain 
			          wrong to store the hostname in this query. */
			
			/* tmp = (char *)PQgetvalue (res, i, 4);
			(*data)[index].machine_name = calloc(1, strlen(tmp)+1);
			
			if ((*data)[index].machine_name == NULL) {
				fprintf (stderr,"%s: calloc(1, size %u) for string \"%s\" failed: %s\n", me, strlen(tmp)+1, tmp, strerror(errno));

				DPRINTF ("calloc(1, size %u) for string \"%s\" failed: %s\n", strlen(tmp)+1, tmp, strerror(errno));

				sql_clear_result ();
				sql_close_connection ();
				exit (-1);
			}
			memcpy((*data)[index].machine_name, tmp, strlen(tmp)+1); */
			(*data)[index].machine_name = NULL;

			(*data)[index].firstrule = NULL;
			r1 = NULL;
		}
		r = new_rule ();
		if (r1 == NULL)
			 (*data)[index].firstrule = r;
		else
			r1->next = r;
		r1 = r;

		// never copy more than MAX_RULE_NAME_LENGTH+1 bytes from the resulting rule name
		strncpy (r->name, sql_result_get_value (i, 0), MAX_RULE_NAME_LENGTH+1);
		// make sure it's a null terminated string
		r->name[MAX_RULE_NAME_LENGTH] = '\0';
		r->bytes = strtoull (sql_result_get_value (i, 1), NULL, 10);
		r->pkts = strtoull (sql_result_get_value (i, 2), NULL, 10);
	}
	sql_clear_result ();

	DPRINTF ("data conversion finished\n");
	DPRINTF ("sql_stor_get_summary returning: %i\n", index+1);
	return index+1;
}

static int sql_stor_delete_record (timestamp_t timestamp)
{
	char wh_exec[120];

	sprintf (wh_exec, "DELETE FROM logs WHERE that_time = '%lu'", timestamp);

	DPRINTF ("sql_stor_delete_record\n");
	return sql_execute_simple_query (wh_exec);
}


/* free data we kept in memory */
static void sql_stor_clear ()
{
	DPRINTF ("sql_stor_clear() \n");

	if (_timestamp_lst != NULL) {
		DPRINTF ("freeing data_record_type array with %i elements\n", _timestamp_max);
		free_data_record_type_array (_timestamp_lst, _timestamp_max);
		_timestamp_lst = NULL;
		_timestamp_max = 0;
	}
	
	if (_rules_lst != NULL) {
		DPRINTF ("freeing rule_type array with %i elements\n", _rules_max);
		free (_rules_lst);
		_rules_lst = NULL;
		_rules_max = 0;
	}
	DPRINTF ("sql_stor_clear finished\n");
}

static void sql_stor_close ()
{
	DPRINTF ("sql_stor_close()\n");

	/* clean up first */
	sql_stor_clear ();

	sql_close_connection ();
	storage_opened = 0;
	DPRINTF ("sql_stor_close finished\n");

#ifdef DEBUG_DB
	/* close logfile */
	if (fd != -1) {
		close (fd);
	}
#endif

}

#ifdef DEBUG_DB
static void debuglog (const char *format, ...)
{
	va_list arg;
	time_t tm;
	char logline[512];
	
	// construct the date string like syslog does, eg. Sep 26 00:23:04
	tm = time(NULL);	
	strftime(logline, sizeof(logline)-1, "%b %e %H:%M:%S ", localtime(&tm));

	snprintf (logline+strlen(logline), sizeof(logline)-strlen(logline)-1, "fetchipac[%i]: ", getpid());
	    
	va_start (arg, format);
	vsnprintf(logline+strlen(logline), sizeof(logline)-strlen(logline)-1, format, arg);
	va_end (arg);

	// write the log message to the logfile
	if (fd != -1) {
		write (fd, logline, strlen(logline));
	}
}
#endif	
