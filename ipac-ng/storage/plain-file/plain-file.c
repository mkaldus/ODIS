/*
 *
 * $Id: plain-file.c,v 1.4 2009/08/02 13:49:41 mdw21 Exp $
 *
 * old "plain file" backend to fetchipac
 * Copyright (C) 1997 - 2000 Moritz Both
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
 * The author can be reached via email: moritz@daneben.de, or by
 * snail mail: Moritz Both, Im Moore 26, 30167 Hannover,
 *             Germany. Phone: +49-511-1610129
 *
 */

#include "ipac.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/param.h>
#include <unistd.h>

/* plain file ipac interface entries */
int plain_file_ipac_open(int flag);
int plain_file_ipac_store_record(const data_record_type *data);
int plain_file_ipac_list_timestamps(timestamp_t start, timestamp_t end,
		timestamp_t **data, timestamp_t *just_before,
		timestamp_t *just_after, char *);
int plain_file_ipac_get_records(timestamp_t timestamp_s,timestamp_t timestamp_e,
		data_record_type **data, char *filter);
int plain_file_ipac_get_summary(timestamp_t timestamp_s,timestamp_t timestamp_e,
                data_record_type **data, char *filter);
int plain_file_ipac_get_raw_list(char *ag_name, char *login, 
		raw_rule_type **data);
int plain_file_ipac_delete_record(timestamp_t timestamp);
void plain_file_ipac_close();

const storage_method_t interface_entry = {
	"plain-file",
	plain_file_ipac_open,
	plain_file_ipac_store_record,
	plain_file_ipac_list_timestamps,
	plain_file_ipac_get_records,
	plain_file_ipac_get_summary,
	plain_file_ipac_delete_record,
	plain_file_ipac_close
};
const storage_method_t *ipac_sm_interface_plain_file() {
	return &interface_entry;
}

/* convert a 'mytime' formatted time (file name in plain-file style
 * database) into a timestamp_t. return -1 in case of error, 0 otherwise.
 */
static int mytime2timestamp_t(const char *s, timestamp_t *t)
{
	struct tm stm;

	if (sscanf(s, "%4d%2d%2d-%2d%2d%2d", 
			&stm.tm_year, &stm.tm_mon, &stm.tm_mday,
			&stm.tm_hour, &stm.tm_min, &stm.tm_sec) != 6)
	{
		/* invalid */
		return -1;
	}

	/* in struct tm, month has range 0...11 */
	stm.tm_mon--;
	/* year is the number of years since 1900 */
	stm.tm_year -= 1900;
	/* the major design flaw of plain-file: we dont know if this
	 * is daylight saving time.
	 */
	stm.tm_isdst = -1;
	if ((*t = mktime(&stm)) == (time_t)-1)
	{
		/* some kind of error. */
		return -1;
	}
	return 0;
}

/* convert a timestamp_t into a mytime string.
 * return 0 for success, -1 for error. s must be an array
 * with at least 16 chars.
 */
static int timestamp_t2mytime(timestamp_t ts, char *s)
{
	struct tm *tmp;

	tmp = localtime(&ts);
	sprintf(s, "%04d%02d%02d-%02d%02d%02d", tmp->tm_year+1900, 
			tmp->tm_mon+1, tmp->tm_mday, 
			tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
	return 0;
}

int plain_file_ipac_open(int flag)
{
	/* nothing to do. */
	return 0;
}

int plain_file_ipac_store_record(const data_record_type *data)
{
	FILE *f;
	char filename[PATH_MAX+20];
	struct tm *tmp;
	int i;
	rule_type *rule, *firstrule;

	tmp = localtime(&data->timestamp);
	firstrule = data->firstrule;

	strncpy(filename, datadir, PATH_MAX-1);
	strcat(filename, "/");
	i = strlen(filename);
	strftime(filename + i, PATH_MAX-i, "%Y%m%d-%H%M%S", tmp);

	f = fopen(filename, "w");
	if (f == NULL)
	{
		fprintf(stderr, "%s: opening \"%s\": %s\n",
			me, filename, strerror(errno));
		return 1;
	}

	for (rule = firstrule; rule; rule=rule->next)
		fprintf(f, "%s\n", rule->name);
	fprintf(f, "%s\n", DATDELIM);
	for (rule = firstrule; rule; rule=rule->next)
		fprintf(f, "%Lu %Lu\n", rule->pkts,
			rule->bytes);
	if (ferror(f))
	{
		fprintf(stderr, "%s: error writing file \"%s\": %s\n",
			me, filename, strerror(errno));
		fclose(f);
		return 1;
	}
	fclose(f);
	return 0;
}

int plain_file_ipac_list_timestamps(timestamp_t start, timestamp_t end,
		timestamp_t **data, timestamp_t *just_before, 
		timestamp_t *just_after, char *ahost)
{
	DIR *d;
	struct dirent *de;
	timestamp_t ts, *ts_list=NULL;
	int ts_list_len = 0;
	int ts_list_used = 0;
/*
	if (!ahost) {
		fprintf(stderr, "%s: accounting hosts is not supported by "
				"'plain-file' storage method\n", me);
		return -1;
	}
*/	
	d = opendir(datadir);
	if (d == NULL) {
		fprintf(stderr, "%s: cant open directory \"%s\": %s\n", me,
				datadir, strerror(errno));
		return -1;
	}
	
	if (just_before != NULL)
		*just_before = (timestamp_t)-1;
	if (just_after != NULL)
		*just_after = (timestamp_t)-1;
	while((de = readdir(d)) != NULL)
	{
		if (de->d_name[0] == '.')
			continue;
		if (mytime2timestamp_t(de->d_name, &ts) != 0)
			continue;
		if (ts < start)
		{
			if (just_before != NULL && 
				(*just_before==(timestamp_t)-1 
					|| *just_before < ts))
				*just_before = ts;
			continue;
		}
		if (ts > end)
		{
			if (just_after != NULL && 
					(*just_after == (timestamp_t)-1
					|| *just_after > ts))
				*just_after = ts;
			continue;
		}

		/* eintragen in ts_list */
		if (ts_list_used == ts_list_len)
		{
			if (ts_list_len == 0)
				ts_list_len = 8;
			ts_list_len <<= 1;
			ts_list = (timestamp_t *)xrealloc(ts_list, 
					ts_list_len * sizeof(timestamp_t));
		}
		ts_list[ts_list_used++] = ts;
	}
	closedir(d);

	/* sort the list */
	qsort(ts_list, ts_list_used, sizeof(timestamp_t), compare_timestamp_t);
	*data = ts_list;

	return ts_list_used;
}

int plain_file_ipac_get_record(timestamp_t timestamp,
		data_record_type *data)
{
	char file[PATH_MAX + 30], *cp;
	FILE *f;
	char buf[MAX_RULE_NAME_LENGTH + 20];
	rule_type *r, *r1, *r2;
	int i;
	UINT64 bytes, packets;

	strncpy(file, datadir, PATH_MAX-1);
	file[PATH_MAX-1] = '\0';
	cp = strchr(file, '\0');
	*cp++ = '/';

	if (timestamp_t2mytime(timestamp, cp) != 0)
		return -1;

	f = fopen(file, "r");
	if (f == NULL)
	{
		fprintf(stderr, "%s: cant open file \"%s\": %s\n", me, file,
				strerror(errno));
		return -1;
	}

	/* create record_data_type. */
	data->timestamp = timestamp;
	data->machine_name = xstrdup(hostname);
	data->firstrule = NULL;

	/* read rule names. */
	r1 = NULL;
	i = 0;
	while(fgets(buf, MAX_RULE_NAME_LENGTH + 20, f) != NULL)
	{
		cp = strchr(buf, '\n');
		if (cp)
			*cp = 0;
		if (strcmp(buf, DATDELIM) == 0)
		{
			i = 1;
			break;		/* end of rule section */
		}
		if (*buf == '#')
			continue;
		
		r = new_rule();
		if (r1 == NULL)
			data->firstrule = r;
		else
			r1->next = r;
		r1 = r;
		strncpy(r->name, buf, MAX_RULE_NAME_LENGTH);
		r->name[MAX_RULE_NAME_LENGTH] = '\0';
	}

	if (i == 0)
	{
		/* end of file without seeing delimiter */
		fprintf(stderr, "%s: end of file \"%s\" without seeing "
				"delimiter \"" DATDELIM "\" / corrupted data\n",
				me, file);
		fclose(f);
//		free_data_record_type_array(*data, 1);
		return -1;
	}

	/* read actual data */
	r = data->firstrule;
	r1 = NULL;		/* remember the rule before the current one in 
				 * r1 */

	while(fgets(buf, MAX_RULE_NAME_LENGTH + 20, f) != NULL)
	{
		if (*buf == '#')
			continue;

		/* try to interpret this line. If that fails, ignore the line
		 * (ipasum does it that way and we need it for old data
		 * files, created with fetchipac before version 1.06 on
		 * ipfwadm machines).
		 */
		packets = 0;
		bytes = 0;
		if (sscanf(buf, " %Lu %Lu", &packets, &bytes) != 2)
		{
			continue;
			/*
			fprintf(stderr, "%s: invalid data line in file \"%s\""
					"\n", me, file);
			*/
		}
		if (r == NULL)
		{
			fprintf(stderr, "%s: more data than rule names in file "
					"\"%s\" / corrupted data\n", me, file);
			break;
		}

		/* if a rule comes twice, we only use the first appearance
		 * counters, all other instances are removed from the list.
		 * to check, we need to compare the current rule name with all
		 * rule names before this one.
		 */
		
		/* rule already known ? */
		for (r2=data->firstrule; r2!=r; r2=r2->next)
		{
			if (strcmp(r2->name, r->name) == 0)
				break;
		}
		if (r2 != r)
		{
			/* found it. remove the current instance from the list.
			 * r1 is the rule before the current one.
			 * r1 cant be NULL since the first rule wont ever be
			 * removed - it cant be equal to a rule before it.
			 */
			r1->next = r->next;
			free(r);
			r = r1;
		}

		/* r2 tells us which counters to increment. */
		r2->bytes += bytes;
		r2->pkts += packets;

		r1 = r;
		r=r->next;
	}	
	fclose(f);
	if (r != NULL)
	{
		/* more rule names than data */
		fprintf(stderr, "%s: more rule names than data in file "
				"\"%s\"\n", me, file);
		/* remove them from the rule list. */
		if (r1 != NULL)
			r1->next = NULL;
		else
			data->firstrule = NULL;
		while(r != NULL)
		{
			r1 = r->next;
			free(r);
			r = r1;
		}
	}
	return 1;
}

int plain_file_ipac_get_summary(timestamp_t timestamp_s,timestamp_t timestamp_e,
                data_record_type **data, char *filter)
{
	fprintf(stderr, "plain file storage does not support summary request\n");
	return -1;
}


int plain_file_ipac_get_records(timestamp_t timestamp_s,timestamp_t timestamp_e,
		data_record_type **data, char *filter)
{
        if (timestamp_e && (timestamp_e != timestamp_s)) {
         //if we have both timestamps and beginning is different from end
        	timestamp_t *tlist;
	        int n, i;

	        n = plain_file_ipac_list_timestamps(timestamp_s-1, timestamp_e, 
								    &tlist,0,0,NULL);
                //FIXME: thou shall not delete accounting files from now until 
						    //end of this function
                *data = (data_record_type *)xmalloc(sizeof(data_record_type)*n);
                for (i=0; i<n; i++) {
                        int r=plain_file_ipac_get_record(tlist[i],(*data)+i);
                        if (r != 1)
		                fprintf(stderr, "plain_file_ipac_get_record did "
				"not return exactly one record, as it should\n");
		}
        	if (n > 0)
	        	free(tlist);
		return n;
        } else {//we have only one timestamp
        	*data = (data_record_type *)xmalloc(sizeof(data_record_type));
		plain_file_ipac_get_record(timestamp_s,*data);
                return 1;
        }
}

int plain_file_ipac_delete_record(timestamp_t timestamp)
{
	char file[PATH_MAX + 30], *cp;

	strncpy(file, datadir, PATH_MAX-1);
	file[PATH_MAX-1] = '\0';
	cp = strchr(file, '\0');
	*cp++ = '/';

	if (timestamp_t2mytime(timestamp, cp) != 0)
		return -1;
	if (unlink(file) != 0)
	{
		fprintf(stderr, "%s: cant unlink \"%s\": %s\n",
				me, file, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * new functions are still not fully supported in plain-file method
 * this function is here for compatibility only - it does not support
 * storage agents and login names. Eats old styled config file
 */
int plain_file_ipac_get_raw_list(char *ag_name, char *login, 
						raw_rule_type **data)
{
	FILE *conf;
	char buf[MAX_RULE_NAME_LENGTH + 100];
	char *tmp, *src, *dst;
	raw_rule_type *r1, *r;
	
	conf = fopen(conffile, "r");
	if (!conf)
	{
		fprintf(stderr, "%s: opening config \"%s\": %s\n",
			me, conffile, strerror(errno));
		return 1;
	}
	r1 = NULL;
	while(fgets(buf, MAX_RULE_NAME_LENGTH + 100, conf))
	{
		if ((*buf=='#')||(*buf=='\n')||(*buf=='\t')||(*buf==' '))
			continue;
		r = new_raw_rule();
		if (r1 == NULL)
			*data = r;
		else
			r1->next = r;
		r1 = r;
		tmp = strtok(buf, "|");		// get rule name
		strncpy(r->name, tmp, MAX_RULE_NAME_LENGTH);
		tmp = strtok(NULL, "|");	// get destination
		strncpy(r->dest, tmp, 5);
		tmp = strtok(NULL, "|");	// get iface
		strncpy(r->iface, tmp, 9);
		tmp = strtok(NULL, "|");	// get protocol
		strncpy(r->protocol, tmp, 5);
		src = strtok(NULL, "|");	// get source address/ports
		dst = strtok(NULL, "|");
		while(strtok(NULL, "|"));	// clean up strtok internals
		tmp = strtok(src, " ");		// split source to address/proto
		strncpy(r->snet, tmp, sizeof(r->snet)-1);
		tmp = strtok(NULL, " ");	// are there any ports?
		if (tmp)
			strncpy(r->sport, tmp, 19);
		while(strtok(NULL, " "));	// clean up
		tmp = strtok(dst, " \n");
		strncpy(r->dnet, tmp, sizeof(r->dnet)-1);
		tmp = strtok(NULL, " \n");
		if (tmp)
			strncpy(r->dport, tmp, 19);
		while(strtok(NULL, " "));
	}
	fclose(conf);	
	return 0;
}

void plain_file_ipac_close()
{
	/* nothing to do. */
}
