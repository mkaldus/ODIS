#ifndef IPACGDBM_H_INCLUDED
#define IPACGDBM_H_INCLUDED
/*
 *
 * $Id: ipac_gdbm.h,v 1.3 2003/09/28 11:24:59 kaiser13 Exp $
 *
 * ipac gdbm storage backend header file
 * Copyright (C) 2000 Moritz Both
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

#include <time.h>
#include "config.h"
#include "ipac.h"

/* define the data file names */
#define GDBM_DATA_DB	"/data.db"
#define GDBM_MACHINE_DB	"/machine.db"
#define GDBM_RULE_DB	"/rule.db"
#define GDBM_TIMESTAMPS	"/timestamps"

/* file locking retry parameters
 * doing it every 2 sec makes 30 retries per minute
 * 300 retries is 10 minutes
 * 1800 retries is an hour
 * we should retry for a long time on writes. 
 * Under heavy load, the database may be
 * locked by readers for longer. We need to store data on write, though -
 * dont want to loose it.
 */
#define GDBM_LOCK_RETRY_DELAY  2  /* sec */
#define GDBM_LOCK_RETRY_TIMES_READ  30
#define GDBM_LOCK_RETRY_TIMES_WRITE 10

/* various types for the storage */

/* timestamp */
typedef struct {
	timestamp_t	ts_l;
	unsigned char	ts_h;	/* future time_t extension */
} PACKED gdbm_timestamp;

/* data.db key type */
typedef gdbm_timestamp 	gdbm_data_key_t;

/* data.db value type: data record header */
typedef struct {
	size_t		length;		/* total length ot data record */
	unsigned int 	machine_id;
	int		flag;
	unsigned int	record_count;
} gdbm_data_value_header_t;
/* possible values for flag in gdbm_data_value_header_t */
#define	DVHF_MORE	1	/* another record follows this one */

/* data.db value type: data record (record_count of them
 * in one entry)
 */
typedef struct {
	UINT64		packets;
	UINT64		bytes;
	unsigned int	rule_id;
} gdbm_data_value_record_t;

/* rule.db and machine.db have the same format */
#define GDBM_REVERSE_FLAG	((char)7)
typedef union {
	struct {
		char magic;	/* GDBM_REVERSE_FLAG */
		char fill[3];
		unsigned int id;
	} numeric;
	char	firstchar;	/* incomplete - this is the start of the string
				 */
} gdbm_lookup_t;

/* function prototypes for api interface */
int gdbm_ipac_open(int flag);
int gdbm_ipac_store_record(const data_record_type *data);
int gdbm_ipac_list_timestamps(timestamp_t start, timestamp_t end,
		timestamp_t **data, timestamp_t *just_before,
		timestamp_t *just_after, char *);
int gdbm_ipac_get_records(timestamp_t timestamp_s, timestamp_t timestamp_e,
		data_record_type **data);
int gdbm_ipac_get_summary(timestamp_t timestamp_s, timestamp_t timestamp_e,
                data_record_type **data);
int gdbm_ipac_delete_record(timestamp_t timestamp);
void gdbm_ipac_close();

#endif
