/*
 *
 * $Id: gdbm.c,v 1.4 2004/04/18 20:26:12 friedl Exp $
 *
 * gdbm backend to ipac
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

The gbdm backend to ipac is organized as follows:

  file name	content
  data.db	gdbm file with keys of type gdbm_data_key_t
  		and values storing the actual ip accounting data
  rule.db	gdbm file with rule name to rule id mapping and vice
  		versa. keys are of type gdbm_rule_key_t and
		values of type gdbm_rule_value_t
  machine.db	gdbm file with machine name to machine id mapping and
  		vice versa. Works like the rule.db file
  timestamps	data file (not gdbm) containing a sorted array of
  		gdbm_timestamps_t's, indicating the timestamps of
		data which can be found in data.db

  The database is network aware and uses gdbm's locking features.
  
  It is assumed that there is no life time mapping of rule names and rule 
ids.  Each time fetchipac runs, it stores one record into data.db . The data.db
records contain the current timestamp (gdbm key), the machine name id, 
an array of rule
data records, and a flag. A rule data record is a numeric rule id, a byte
count, and a packet count. The flag has currently only one used bit which
indicates a following record with the same timestamp, possibly from another
machine. If this bit is set, there is another record directly following the
current one, with the same structure.

  rule.db contains each rule twice. One time, the rule name string with all
letters in lower case is the key, and the value is a 32 bit integer indicating
the rule id. The second time, the id is the key and the value is the rule
name. Whenever the id is the key, it has a BEL character (ASCII 7) prepended
to distinguish from a valid rule name.

  machine.db contains each machine twice. The machine name comes from the
gethostbyname() call, and every machine gets its own id. The rest works as
in the rule.db file.

  timestamps contains a sorted array of 40 bit timestamp values. Those
values are standard unix time (seconds since 1970 January 1st, midnight, GMT).
After the year 2000 hassle, we designed it so that no data must be converted
when we have more than 32 bits for the timestamp. So far, only 32 bits are
used. Each record "points" to a record in data.db, where the corresoponding
data record can be fetched from. The file helps to speed up retrieval of data
since gdbm can't list all keys in sorted order. 

The file is sorted so fetchipac can simply add at the end. Whenever data 
records are deleted from data.db, the corresponding entry in timestamps can
be left alone - if the data.db entry no longer exists, there is no data.
If, however, a data record is added to data.db out of order, for example,
when data.db data is compressed (ipacsum --replace), we need to add the
corresponding record to timestamps. This might make it neccessary to re-
write it completely. The file can be generated from data.db anytime,
however. A function to do this needs to be written. - timestamps is considered
locked whenever the data.db is locked.
 *
 */

#include <gdbm.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>

#include "config.h"
#include "ipac.h"
#include "ipac_gdbm.h"


/* names of the data files */
static char *filename_data_db = NULL;
static char *filename_machine_db = NULL;
static char *filename_rule_db = NULL;
static char *filename_timestamps = NULL;

/* pointers to open streams */
static GDBM_FILE fdatadb = NULL;
static GDBM_FILE fmachinedb = NULL;
static GDBM_FILE fruledb = NULL;
static FILE *ftimestamps = NULL;

/* the interface entry to ipac */
static const storage_method_t interface_entry = {
	"gdbm",
	gdbm_ipac_open,
	gdbm_ipac_store_record,
	gdbm_ipac_list_timestamps,
	gdbm_ipac_get_records,
	gdbm_ipac_get_summary,
	gdbm_ipac_delete_record,
	gdbm_ipac_close
};


/* the interface function */
const storage_method_t *ipac_sm_interface_gdbm() {
	return &interface_entry;
}


/* print a gdbm error message. */
static void print_gdbm_error(char *format, ...)
{
	va_list vl;

	fprintf(stderr, "%s: ", me);
	va_start(vl, format);
	vfprintf(stderr, format, vl);
	va_end(vl);
	fprintf(stderr, ": %s / %s\n", gdbm_strerror(gdbm_errno),
			strerror(errno));
}

/** called whenever corrupted data is detected. */
static void data_corrupted()
{
	fprintf(stderr, "%s: data corrupted\n", me);
	fflush(stdout);
	fflush(stderr);
	kill(getpid(), SIGSEGV);
}

/** open a gdbm file. wait if it's locked
 * @param file the name of the file to be opened
 * @param read_write if 0, open read only. if 1, open read/write
 * @return The gdbm handle of the file or NULL on failure
 */
static GDBM_FILE ipac_open_gdbm(char *file, int read_write)
{
	GDBM_FILE 	dbfile;
	int		retry;
	gdbm_error	old_gdbm_errno;
	int		i;

	dbfile = gdbm_open(file, 1024, read_write, 0644, 0);
	if (dbfile == NULL) {
		retry = 0;
		old_gdbm_errno = gdbm_errno;
		if (read_write == GDBM_READER
				&& old_gdbm_errno == GDBM_CANT_BE_READER)
			retry = GDBM_LOCK_RETRY_TIMES_READ;
		else if ((read_write == GDBM_WRITER 
					|| read_write == GDBM_WRCREAT)
				&& old_gdbm_errno == GDBM_CANT_BE_WRITER)
			retry = GDBM_LOCK_RETRY_TIMES_WRITE;

		if (retry > 0)
		{
			for (i=0; i<retry; i++)
			{
				sleep(GDBM_LOCK_RETRY_DELAY);
				dbfile = gdbm_open(file, 10240, read_write, 
						0644, 0);
				if (dbfile != NULL 
						|| gdbm_errno != old_gdbm_errno)
					break;
			}
		}
	}
	if (dbfile == NULL)
	{
		fprintf(stderr, "%s: cant open \"%s\": %s / %s\n",
				me, file, gdbm_strerror(gdbm_errno),
				strerror(errno));
	}
	return dbfile;
}

/* get id by name in gdbm file f. if name does not exist, create it.
 * return 0 in case of failure.
 */
static unsigned int get_id_by_name(GDBM_FILE f, char *name)
{
	datum dkey, dvalue;
	gdbm_lookup_t lookup;
	unsigned int v;
	int name_len;

	memset(&lookup, 0, sizeof(lookup));
	dkey.dptr = name;
	name_len = strlen(name) + 1;
	dkey.dsize = name_len;
	dvalue = gdbm_fetch(f, dkey);
	if (dvalue.dptr == NULL)
	{
		/* not found. find maximum id record */
		dkey.dptr = (char *)&lookup;
		lookup.numeric.magic = GDBM_REVERSE_FLAG;
		lookup.numeric.id    = 0;
		dkey.dsize = sizeof(lookup);
		dvalue = gdbm_fetch(f, dkey);
		if (dvalue.dptr == NULL)
		{
			/* even that not found. create the 0 record */
			v = 1;
			dvalue.dptr = (char *)&v;
			dvalue.dsize = sizeof(v);
			if (gdbm_store(f, dkey, dvalue, GDBM_INSERT) != 0)
			{
				print_gdbm_error("cant create max id record in"
						" database file");
				v = 0;
			}
		}
		else
		{
			v = *(unsigned int *)(dvalue.dptr);
			free(dvalue.dptr);
			v++;
			dvalue.dptr = (char *)&v;
			dvalue.dsize = sizeof(v);
			if (gdbm_store(f, dkey, dvalue, GDBM_REPLACE) != 0)
			{
				print_gdbm_error("cant replace max id record "
						"in database file");
				v = 0;
			}
		}

		/* now we have a new id v, or v is 0 */
		if (v != 0)
		{
			lookup.numeric.id = v;
			dvalue.dptr = name;
			dvalue.dsize = name_len;
			if (gdbm_store(f, dkey, dvalue, GDBM_INSERT) != 0)
			{
				print_gdbm_error("cant insert record in databa"
						"se file (name by id)");
				v = 0;
			}
		}

		if (v != 0)
		{
			dkey.dptr = name;
			dkey.dsize = name_len;
			dvalue.dsize = sizeof(v);
			dvalue.dptr = (char *)&v;
			if (gdbm_store(f, dkey, dvalue, GDBM_INSERT) != 0)
			{
				print_gdbm_error("cant insert record in databa"
						"se file (id by name)");
				v = 0;
			}
		}
	}
	else
	{
		/* found rule */
		v = *((unsigned int *)(dvalue.dptr));
		free(dvalue.dptr);
	}
	return v;
}

/* get name by id in gdbm file f.
 * return NULL in case of failure or if id does not exist.
 * return dynamically allocated null terminated string with name
 * otherwise.
 */
static char * get_name_by_id(GDBM_FILE f, unsigned int id)
{
	datum dkey, dvalue;
	gdbm_lookup_t lookup;
	memset(&lookup, 0, sizeof(lookup));

	lookup.numeric.magic = GDBM_REVERSE_FLAG;
	lookup.numeric.id = id;
	dkey.dptr = (char *)&lookup;
	dkey.dsize = sizeof(lookup);
	dvalue = gdbm_fetch(f, dkey);

	/* make sure the string is null terminated */
	if (dvalue.dptr != NULL)
		dvalue.dptr[dvalue.dsize-1] = '\0';
	return dvalue.dptr;
}


/* add timestamp into timestamps file.
 * the data file must be opened and locked - its lock is
 * valid for the timestamps file, too!
 * Return value: 0 for success (the record has been added),
 * -1 for error (which has already been printet to the user),
 * and 1 for the case where the record already existed.
 */
static int add_timestamp(gdbm_timestamp *ts)
{
	struct stat statbuf;
	gdbm_timestamp *tsold, *tsold_buffer, *tsoldnew;
	int tsold_allocated, tsold_index, tsold_allocated_new;
	long offset;
	int exists;
	int n;

	if (fstat(fileno(ftimestamps), &statbuf) != 0)
	{
		fprintf(stderr, "%s: cant fstat \"%s\" fd=%d: "
				"%s\n", me, filename_timestamps,
				fileno(ftimestamps), strerror(errno));
		return -1;
	}

	/* seek from end timestamp that is older than the
	 * new one. Assume that we probably won't have to move
	 * items and we simply can append (for optimization).
	 */
	/* offset from file end as positive number */
	offset = sizeof(gdbm_timestamp);
	exists = 0;
	tsold_allocated = 0;
	tsold_index = 0;
	tsold_buffer = NULL;
	while (statbuf.st_size >= offset)
	{
		if (fseek(ftimestamps, -offset, SEEK_END) != 0)
		{
			fprintf(stderr, "%s: can fseek to offset %ld (SEEK_END)"
					" in "
					"\"%s\": %s\n",
					me, -offset, filename_timestamps,
					strerror(errno));
			return -1;
		}
		/* we remember all the timestamps we read in case we have
		 * to write them out again.
		 * tsold is a dynamic array for that which is resized
		 * whenever neccessary. The array grows in the "wrong"
		 * direction since we read the file in the wrong direction,
		 * too.
		 */
		if (tsold_index == 0)
		{
			/* make room for more of them */
			tsold_allocated_new = tsold_allocated ?
				(tsold_allocated << 1) : 16;
			tsoldnew = (gdbm_timestamp *)
					xrealloc(tsold_buffer,
					sizeof(gdbm_timestamp) 
					* tsold_allocated_new);
			memmove(tsoldnew +(tsold_allocated_new-tsold_allocated),
					tsoldnew,
					tsold_allocated*sizeof(gdbm_timestamp));
			tsold_index = tsold_allocated_new - tsold_allocated;
			tsold_buffer = tsoldnew;
			tsold_allocated = tsold_allocated_new;
		}

		tsold = &tsold_buffer[--tsold_index];
		if (fread(tsold, sizeof(gdbm_timestamp), 1, ftimestamps) != 1)
		{
			fprintf(stderr, "%s: cant read item from "
					"\"%s\": %s\n",
					me, filename_timestamps,
					ferror(ftimestamps) ? strerror(errno)
					: "end of file");
			return -1;
		}

		/* see if they are equal. if so, set exists and leave the
		 * loop.
		 */
		if (tsold->ts_h == ts->ts_h && tsold->ts_l == ts->ts_l)
		{
			exists = 1;
			break;
		}

		/* see if the old one is smaller and in that case leave
		 * the loop. 
		 */
		if (tsold->ts_h < ts->ts_h || (tsold->ts_h == ts->ts_h 
				&& tsold->ts_l <= ts->ts_l))
			break;

		offset += sizeof(gdbm_timestamp);
	}
	/* now offset is the offset in the file from the end where the
	 * element lives that is smaller than the new one. If there is no
	 * such element, offset is sizeof(gdbm_timestamp) higher than the
	 * file length.
	 * Or, exists is 1 - the record already is in the file.
	 */
	if (exists)
	{
		free(tsold_buffer);
		return 1;
	}

	/* write our record. */
	offset -= sizeof(gdbm_timestamp);
	if (fseek(ftimestamps, -offset, SEEK_END) != 0)
	{
		fprintf(stderr, "%s: can fseek to offset %ld (SEEK_END)"
				" in "
				"\"%s\": %s\n",
				me, -offset, filename_timestamps,
				strerror(errno));
error_exit_with_free_tsold:
		free(tsold_buffer);
		return -1;
	}
	if (fwrite(ts, sizeof(gdbm_timestamp), 1, ftimestamps) != 1)
	{
		fprintf(stderr, "%s: cant write item to "
				"\"%s\": %s\n",
				me, filename_timestamps,
				ferror(ftimestamps) ? strerror(errno)
				: "end of file");
		goto error_exit_with_free_tsold;
	}

	if (offset > 0)
	{
		/* move all records "above" ours one item "up". */
		n = tsold_allocated - tsold_index - 1;
		if (fwrite(&tsold_buffer[tsold_index+1], 
				sizeof(gdbm_timestamp), n, ftimestamps) != n)
		{
			fprintf(stderr, "%s: cant write %d items to "
					"\"%s\": %s\n",
					me, n, filename_timestamps,
					ferror(ftimestamps) ? strerror(errno)
					: "end of file");
			goto error_exit_with_free_tsold;
		}
	}
	free(tsold_buffer);
	fflush(ftimestamps);
	fdatasync(fileno(ftimestamps));
	return 0;
}

/* initialize the gdbm files. Possibly create them if they don't exist.
 */
static void gdbm_init() 
{
	static int init_done = 0;
	int i;

	if (init_done == 0)
	{
		/* removed hardcoded check for variable length which breaks 
		 * on 64 bit machines
		 * 18.04.2004 - Thomas Zehetbauer <thomasz@hostmaster.org>
		 */
		 
		/* set the file names. */
		i = strlen(datadir) + 1;
		filename_machine_db =(char *)xmalloc(i+sizeof(GDBM_MACHINE_DB));
		strcpy(filename_machine_db, datadir);
		strcat(filename_machine_db, GDBM_MACHINE_DB);
		filename_rule_db = (char *)xmalloc(i + sizeof(GDBM_RULE_DB));
		strcpy(filename_rule_db, datadir);
		strcat(filename_rule_db, GDBM_RULE_DB);
		filename_data_db = (char *)xmalloc(i + sizeof(GDBM_DATA_DB));
		strcpy(filename_data_db, datadir);
		strcat(filename_data_db, GDBM_DATA_DB);
		filename_timestamps =(char *)xmalloc(i+sizeof(GDBM_TIMESTAMPS));
		strcpy(filename_timestamps, datadir);
		strcat(filename_timestamps, GDBM_TIMESTAMPS);
		
		init_done = 1;
	}
}
/** check if timestamp t is valid. return 0 for valid, 1 for not valid,
 * -1 for error. valid means, there is an entry in the data.db file.
 */
static int check_timestamp(const gdbm_timestamp *t)
{
	datum dkey;

	dkey.dptr = (char *)t;
	dkey.dsize = sizeof(gdbm_timestamp);
	return gdbm_exists(fdatadb, dkey) ? 0 : 1;
}

/**find a bigger timestamp in the timestamps file. 
 * use a binary search.
 * @param timestamp the timestamp to be looked for.
 * @param offset return offset in the timestamps file in *offset.
 * @return return value is 0 for success, -1 for error.
 */
static int find_timestamp(timestamp_t timestamp, unsigned long *offset)
{
	struct stat statbuf;
	unsigned long low, high, current;
	gdbm_timestamp t1;

	if (fstat(fileno(ftimestamps), &statbuf) != 0)
	{
		fprintf(stderr, "%s: cant fstat \"%s\" fd=%d: "
				"%s\n", me, filename_timestamps,
				fileno(ftimestamps), strerror(errno));
		return -1;
	}

	low = 0;
	high = statbuf.st_size/sizeof(gdbm_timestamp);

	while(low < high)
	{
		current = low + (high - low) / 2;
		*offset = current * sizeof(gdbm_timestamp);
		if (*offset >= statbuf.st_size)
			break;
		if (fseek(ftimestamps, *offset, SEEK_SET) != 0) {
			fprintf(stderr, "%s: cant fseek on timestamps file to "
					"offset %lu\n", me, *offset);
			return -1;
		}
		if (fread(&t1, sizeof(t1), 1, ftimestamps) != 1) {
			fprintf(stderr, "%s: cant read from timestamps file:"
					"%s\n", me, feof(ftimestamps) ?
					"EOF" : strerror(errno));
			return -1;
		}
// was '<=' i've changed it to '<' Kaiser
		if (t1.ts_l < timestamp)
			low = current + 1;
		else
			high = current;
	}
	*offset = high * sizeof(gdbm_timestamp);
	return 0;
}

/** find the next valid timestamp. 
 * A timestamp is valid if there is a mathing
 * entry in data.db . 
 * @param offset start at *offset which is an offset 
 * into the timestamps file. 
 * @param backward travel forward
 * (0) or backward (not 0) through the timestamps file. 
 * @param tp points to a location where on success the timestamp found 
 * is stored
 * @return 1 on success and set *offset to the offset of the timestamp found.
 * return 0 if end of file or beginning of file is reached. return -1
 * on error.
 */
static int timestamp_step(unsigned long *offset, int backward, 
		gdbm_timestamp *tp)
{
	struct stat statbuf;
	const int cachesize = 1024/sizeof(gdbm_timestamp);
	const int cachebytes = cachesize * sizeof(gdbm_timestamp);
	gdbm_timestamp cache[cachesize];
	unsigned long cache_start;


	fflush(ftimestamps);
	if (fstat(fileno(ftimestamps), &statbuf) != 0)
	{
		fprintf(stderr, "%s: can stat timestamps file: %s\n", me,
				strerror(errno));
		return -1;
	}

	cache_start = (unsigned long) -1;
	for(;;) {
		if (backward == 0)
		{
			*offset += sizeof(gdbm_timestamp);
			if (*offset >= statbuf.st_size)
				return 0;	/* end of file */
		}
		else
		{
			if (*offset == 0)
				return 0;	/* start of file */
			*offset -= sizeof(gdbm_timestamp);
		}

		/* read this thing. we always read cachesize
		 * items at once, minimizing the number of system calls.
		 */
		if (cache_start > *offset || cache_start+cachebytes 
				<= *offset)
		{
			/* fill the cache */
			cache_start = *offset;
			if (backward != 0)
			{
				if (cache_start >= cachebytes)
					cache_start -= cachebytes
						-sizeof(gdbm_timestamp);
				else
					cache_start = 0;
			}
			if (fseek(ftimestamps, cache_start, SEEK_SET) != 0)
			{
				fprintf(stderr, "%s: cant fseek on timestamps "
						"file to offset %lu: %s\n", me, 
						cache_start,strerror(errno));
				return -1;
			}
			if (fread(cache, sizeof(gdbm_timestamp), cachesize,
					ftimestamps) == 0)
			{
				fprintf(stderr, "%s: cant read from timestamps "
						"file: %s\n", me,
						strerror(errno));
				return -1;
			}
		}
		if (check_timestamp(cache + (*offset - cache_start)
				/ sizeof(gdbm_timestamp)) ==0)
		{
			*tp = *(cache + (*offset - cache_start)
				/sizeof(gdbm_timestamp));
			return 1;
		}
	}

	/* NEVERREACHED */
}

/** rebuild the timestamps file. this is build up from the data.db file
 *  it is basically a sorted list of timestamp values which may appear
 *  as keys in data.db
 */
static int compare_gdbm_timestamp(const void *p1, const void *p2)
{
	if (((gdbm_timestamp *)p1)->ts_h != ((gdbm_timestamp *)p2)->ts_h)
		return ((gdbm_timestamp *)p1)->ts_h
				- ((gdbm_timestamp *)p2)->ts_h;
	return ((gdbm_timestamp *)p1)->ts_l - ((gdbm_timestamp *)p2)->ts_l;
}
static int rebuild_timestamps()
{
	unsigned int array_length = 0;
	unsigned int array_index = 0;
	gdbm_timestamp *array = NULL;
	datum dkey, newkey;

	dkey = gdbm_firstkey(fdatadb);
	
	while(dkey.dptr != NULL)
	{
		if (array_index >= array_length)
		{
			array_length = (array_length ? (array_length<<1) : 16);
			array = (gdbm_timestamp *) xrealloc(array, 
					array_length * sizeof(gdbm_timestamp));
		}
		array[array_index++] = *(gdbm_timestamp *)dkey.dptr;
		newkey = gdbm_nextkey(fdatadb, dkey);
		free(dkey.dptr);
		dkey = newkey;
	}

	qsort(array, array_index, sizeof(gdbm_timestamp),
			compare_gdbm_timestamp);
	if (fseek(ftimestamps, 0, SEEK_SET) != 0)
	{
		fprintf(stderr, "%s: cant seek on timestamps file: %s\n",
				me, strerror(errno));
		exit(1);
	}
	if (fwrite(array, sizeof(gdbm_timestamp), array_index, ftimestamps)
			!= array_index)
	{
		fprintf(stderr, "%s: cant write %u elements to timestmaps "
				"file: %s\n", me, array_index, 
				strerror(errno));
		exit(1);
	}
	fflush(ftimestamps);
	ftruncate(fileno(ftimestamps), sizeof(gdbm_timestamp)*array_index);

	return 0;
	
}


/*************************************************************************
 * API - functions that are called by main programs
 */

void gdbm_ipac_close();

int gdbm_ipac_open(int flag)
{
	int of;
	const char *msg;
	struct stat stat_buf;
	int fd = -1;

	if (flag & SM_OPEN_READONLY) {
		of = GDBM_READER;
		msg = "reading";
	} else {
		of = GDBM_WRCREAT;
		msg = "writing";
	}
	gdbm_init();
	gdbm_ipac_close();

	fdatadb = ipac_open_gdbm(filename_data_db, of);
	if (fdatadb == NULL) {
		print_gdbm_error("cant open database file \"%s\" for %s",
					filename_data_db, msg);
		return -1;
	}
	fruledb = ipac_open_gdbm(filename_rule_db, of);
	if (fruledb == NULL)
	{
		print_gdbm_error("cant open database file \"%s\" for %s",
				filename_rule_db, msg);
open_error_out:
		gdbm_ipac_close();
		return -1;
	}
	if (stat(filename_timestamps, &stat_buf) != 0)
	{
		if (errno == ENOENT)
		{
			if ((flag & SM_OPEN_READONLY) == 0)
			{
				fd = creat(filename_timestamps, 0666);
				if (fd < 0)
				{
					fprintf(stderr, "%s: cant create tim"
							"estmaps file \"%s\""
							": %s\n", me, 
							filename_timestamps,
							strerror(errno));
					goto open_error_out;
				}
				close(fd);
			}
		} else {
			fprintf(stderr, "%s: cant stat timestmps file \"%s\":"
					"%s\n", me, filename_timestamps, 
					strerror(errno));
			goto open_error_out;
		}
	}

	ftimestamps = fopen(filename_timestamps, 
			(flag & SM_OPEN_READONLY) ? "rb" : "rb+");
	if (ftimestamps == NULL) {
		fprintf(stderr, "%s: cant open timestamps file \"%s\" for %s:"
				" %s\n",
				me, filename_timestamps, msg, 
				strerror(errno));
		goto open_error_out;
	}

	fmachinedb = ipac_open_gdbm(filename_machine_db, of);
	if (fmachinedb == NULL) {
		print_gdbm_error("cant open database file \"%s\" for %s",
					filename_machine_db, msg);
		goto open_error_out;
	}

	/* if timestamps file was created rebuild its contents.
	 */
	if (fd > -1)
		rebuild_timestamps();

	return 0;
}

int gdbm_ipac_store_record(const data_record_type *data)
{
	gdbm_timestamp	timestamp;
	int rule_count, have_old_record, i;
	size_t size;
	datum dkey, dvalue;
	rule_type *rulep;
	gdbm_data_value_header_t *data_value_header_p = NULL;
	gdbm_data_value_record_t *data_value_record_p = NULL;
	char *cp;
	unsigned long id;
	unsigned long machine_id;

	/* get machine id by name. */
	machine_id = get_id_by_name(fmachinedb, data->machine_name);
	if (machine_id == 0) {
		fprintf(stderr, "%s: cant get machine id for \"%s\"\n",
				me, data->machine_name);
		return -1;
	}

	/* store timestamp info timestamps */
	timestamp.ts_l = data->timestamp;
	timestamp.ts_h = 0;
	have_old_record = add_timestamp(&timestamp);
	if (have_old_record == -1) {
		/* failed for some reason */
		return -1;
	}
	dkey.dptr = (char *)&timestamp;
	dkey.dsize = sizeof(timestamp);
	dvalue.dptr = NULL;
	dvalue.dsize = 0;
	if (have_old_record == 1) {
		/* was already there. add to the end */
		dvalue = gdbm_fetch(fdatadb, dkey);
		if (dvalue.dptr == NULL) {
			have_old_record = 0;
			dvalue.dsize = 0;
		}
	}

	/* count the rules. */
	for (rule_count=0, rulep=data->firstrule; rulep!=NULL; 
			rulep=rulep->next, rule_count++);

	/* allocate memory for the new record. */
	size = (dvalue.dptr != NULL ? dvalue.dsize : 0)
		+ sizeof(gdbm_data_value_header_t)
		+ sizeof(gdbm_data_value_record_t) * rule_count;
	dvalue.dptr = xrealloc(dvalue.dptr, size);

	/* if there is already a record with this timestamp, set its
	 * flag to DVHF_MORE
	 */
	if (have_old_record == 1)
	{
		/* do it on the last record there only. */
		i = 0;
		cp = dvalue.dptr;
		while(i+4<dvalue.dsize)
		{
			data_value_header_p = 
					(gdbm_data_value_header_t*)(cp+i);
			if ((data_value_header_p->flag & DVHF_MORE) == 0)
				break;
			i += data_value_header_p->length;
		}
		if (i+4>=dvalue.dsize)
		{
			/* data corrupted. Too bad. */
			fprintf(stderr, "%s: corrupted data - timestamp=%lu\n",
					me, data->timestamp);
			/* what do we do now? */
			data_corrupted();
			have_old_record = 0;
			size -= dvalue.dsize;
			dvalue.dsize = 0;
		}
		else
			data_value_header_p->flag |= DVHF_MORE;
	}

	data_value_header_p = (gdbm_data_value_header_t*)
			(((char*)dvalue.dptr) + dvalue.dsize);
	data_value_header_p->length = size - dvalue.dsize;
	data_value_header_p->machine_id = machine_id;
	data_value_header_p->flag = 0;
	data_value_header_p->record_count = rule_count;

	data_value_record_p = (gdbm_data_value_record_t *)
				(((char *)data_value_header_p)
				+ sizeof(gdbm_data_value_header_t));
	for (rulep=data->firstrule; rulep != NULL; 
			rulep=rulep->next, data_value_record_p++)
	{
		id = get_id_by_name(fruledb, rulep->name);
		if (id == 0)
		{
			fprintf(stderr, "%s: cant get rule id for rule "
					"\"%s\"\n", me, rulep->name);
			goto error_exit_with_free;
		}
		data_value_record_p->rule_id = id;
		data_value_record_p->packets = rulep->pkts;
		data_value_record_p->bytes = rulep->bytes;
	}

	/* store the thing now! */
	dvalue.dsize = size;
	if (gdbm_store(fdatadb, dkey, dvalue, GDBM_REPLACE) != 0)
	{
		print_gdbm_error("cant store data record into \"%s\"",
				filename_data_db);
error_exit_with_free:
		free(dvalue.dptr);
		return -1;
	}
		
	free(dvalue.dptr);
	return 0;
}

/* list the timestamps. */
int gdbm_ipac_list_timestamps(timestamp_t start, timestamp_t end, 
		timestamp_t **data, timestamp_t *just_before,
                        timestamp_t *just_after, char *ahost)
{
	unsigned long ostart, oend;
	int n, i;
	gdbm_timestamp *p, *p1, gt;
	timestamp_t *tsp;

/*
 * 	if (!ahost) {
		fprintf(stderr, "Accounting hosts not supported by gdbm. Switch to postgre\n");
		return -1;
	}
*/	
	if (find_timestamp(start, &ostart) != 0)
		return -1;
	if (find_timestamp(end+1, &oend) != 0)
		return -1;

	/* concerning accuracy. find_timestamp() finds the offset for the
	 * smallest existing timestamp which is bigger than the
	 * argument. This is just the right thing for ostart; *just_before
	 * must be set to the existing timestamp before this one. oend is
	 * pointing to the timestamp which follows the last one we need
	 * to return. For *just_before, we must start to look for a valid
	 * timestamp at end.
	 * Another point to keep in mind is that the timestamps file lists
	 * more timestamps than actually exist in data.db. We need to
	 * check for existance for every timestamp.
	 */
	
	if (oend < ostart)
		return -1;	/* end < start = error */

	/* find the number of potential timestamps */
	n = (oend - ostart) / sizeof(gdbm_timestamp);

	/* there are no data */	
	if (n<1)
		return 0;	// no error when there are no data

	*data = (timestamp_t *)xmalloc(n * sizeof(timestamp_t));
	p = (gdbm_timestamp *)xmalloc((n) * sizeof(gdbm_timestamp));

	/* seek to time stamp ostart */
	if (fseek(ftimestamps, ostart, SEEK_SET) != 0)
	{
		fprintf(stderr, "%s: cant fseek in timestamps file to offset "
				"%lu: %s\n", me, ostart, strerror(errno));
		free(p);
		free(*data);
		return -1;
	}
	if (fread(p, sizeof(gdbm_timestamp), n, ftimestamps) != n)
	{
		fprintf(stderr, "%s: cant read %d items from timestamps file:"
				" %s\n", me, n, feof(ftimestamps) ?
				"EOF" : strerror(errno));
		free(p);
		free(*data);
		return -1;
	}

	
	for (i=0, p1 = p, tsp = *data; i<n; i++, p1++)
	{
		if (check_timestamp(p1) == 0)
			*tsp++ = p1->ts_l;
	}
	free(p);

	if (just_before != NULL)
	{
		i = timestamp_step(&ostart, 1, &gt);
		switch(i)
		{
			case -1: free(*data); return -1;
			case 0:  *just_before = (timestamp_t)-1; break;
			case 1:  *just_before = gt.ts_l; break;
		}
	}
	if (just_after != NULL)
	{
		oend -= sizeof(gdbm_timestamp);
		i = timestamp_step(&oend, 0, &gt);
		switch(i)
		{
			case -1: free(*data); return -1;
			case 0:  *just_after = (timestamp_t)-1; break;
			case 1:  *just_after = gt.ts_l; break;
		}
	}

	return tsp-*data;
}

int gdbm_ipac_get_record(timestamp_t timestamp, data_record_type *data)
{
	datum dkey, dvalue;
	gdbm_data_key_t key;
	gdbm_data_value_header_t *header;
	gdbm_data_value_record_t *record;
	int n, offset, i, i1;
	data_record_type *dr;
	rule_type *rp, *rp1;
	char *cp;
	
	key.ts_h = 0;
	key.ts_l = timestamp;
	dkey.dptr = (char *)&key;
	dkey.dsize = sizeof(gdbm_data_key_t);
	dvalue = gdbm_fetch(fdatadb, dkey);
	n = 0;
	/* count the records. */
	header = (gdbm_data_value_header_t *)dvalue.dptr;
	if (header != NULL)
	{
		/* count records, checking completeness. */
		for(;;) {
			offset = ((char *)header) - dvalue.dptr;
			if (offset +sizeof(gdbm_data_value_header_t)
						> dvalue.dsize
					|| offset 
					+ sizeof(gdbm_data_value_header_t)
					+ header->record_count 
					  * sizeof(gdbm_data_value_record_t)
					> dvalue.dsize)
			{
				data_corrupted();
				break; /* bad data */
			}
			n++;
			if ((header->flag & DVHF_MORE) == 0)
				break;
			header = (gdbm_data_value_header_t *)
					(((char *)header) + header->length);
		}

		if (n>1) {
			fprintf(stderr, "GDBM storage returned too many data for timestamp %lu "
								"Aborting\n", timestamp );
			data_corrupted();	// throu SIGSEGV
		}
					
		/* allocate array of n data_record_type's. */
//		data = (data_record_type *)xmalloc(sizeof(data_record_type));

		/* for each record, fill in data from the dvalue. */
		header = (gdbm_data_value_header_t *)dvalue.dptr;
		dr = data;
		for (i=0; i<n; i++)
		{
			dr->timestamp = timestamp;
			dr->machine_name = get_name_by_id(fmachinedb, 
					header->machine_id);
			dr->firstrule = NULL;
			rp1 = NULL;
			record = (gdbm_data_value_record_t *)(((char *)header) 
					+ sizeof(gdbm_data_value_header_t));
			for (i1=0; i1 < header->record_count; i1++)
			{
				rp = (rule_type *)xmalloc(sizeof(rule_type));
				cp = get_name_by_id(fruledb, record->rule_id);
				if (cp == NULL)
				{
					data_corrupted();
					cp = xstrdup(
						"<rule name not available>");
				}
				strncpy(rp->name, cp, MAX_RULE_NAME_LENGTH);
				rp->name[MAX_RULE_NAME_LENGTH] = '\0';
				free(cp);
				rp->bytes = record->bytes;
				rp->pkts  = record->packets;
				rp->next  = NULL;
				if (dr->firstrule == NULL)
					dr->firstrule = rp;
				else
					rp1->next = rp;
				rp1 = rp;
				record++;
			}
			dr++;
			header = (gdbm_data_value_header_t *)
					(((char *)header) + header->length);
		}
	}
	return n;
}

int gdbm_ipac_get_summary(timestamp_t timestamp_s, timestamp_t timestamp_e,
				data_record_type **data)
{
	fprintf(stderr, "gdbm storage does not support summary request\n");
	return -1;
}

int gdbm_ipac_get_records(timestamp_t timestamp_s, timestamp_t timestamp_e,
				data_record_type **data)
{
        if (timestamp_e && (timestamp_e != timestamp_s)) {
         //if we have both timestamps and beginning is different from end
        	timestamp_t *tlist;
	        int n, i;

	        n = gdbm_ipac_list_timestamps(timestamp_s-1, timestamp_e,
								    &tlist,0,0,NULL);
                //FIXME: thou shall not delete accounting files from now until 
						    //end of this function
                *data = (data_record_type *)xmalloc(sizeof(data_record_type)*n);
                for (i=0; i<n; i++) {
                        int r = gdbm_ipac_get_record(tlist[i],(*data)+i);
                        if (r != 1)
		                fprintf(stderr, "gdbm_ipac_get_record did "
				"not return exactly one record, as it should\n");
		}
        	if (n > 0)
	        	free(tlist);
		return n;
        } else {	//we have only one timestamp
        	*data = (data_record_type *)xmalloc(sizeof(data_record_type));
		gdbm_ipac_get_record(timestamp_s, *data);
                return 1;
        }
}

int gdbm_ipac_delete_record(timestamp_t timestamp)
{
	gdbm_data_key_t key;
	datum dkey;
	int ret;

	memset(&key, 0, sizeof(key));
	key.ts_h = 0;
	key.ts_l = timestamp;
	dkey.dptr = (char *)&key;
	dkey.dsize = sizeof(key);
	ret = gdbm_delete(fdatadb, dkey);
	if (ret != 0)
		print_gdbm_error("cant delete data record");
	return ret;
}

void gdbm_ipac_close()
{
	if (fmachinedb != NULL)
	{
		gdbm_close(fmachinedb);
		fmachinedb = NULL;
	}
	if (fruledb != NULL)
	{
		gdbm_close(fruledb);
		fruledb = NULL;
	}
	if (ftimestamps != NULL)
	{
		fclose(ftimestamps);
		ftimestamps = NULL;
	}
	if (fdatadb != NULL)
	{
		gdbm_close(fdatadb);
		fdatadb = NULL;
	}
}


#ifdef TEST_GDBM
const char *me;
int main(int argc, char **argv) {
	me = argv[0];
	gdbm_init();
	gdbm_store_record(NULL, time(NULL));
	printf("m id: %u\n", machine_id);
	return 0;
}
#endif
