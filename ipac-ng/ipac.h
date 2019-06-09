#ifndef IPAC_H_INCLUDED
#define IPAC_H_INCLUDED
/*
 *
 * $Id: ipac.h,v 1.8 2009/08/02 13:49:41 mdw21 Exp $
 *
 * ipac global header file for c porgrams
 * Copyright (C) 1997 - 2000 Moritz Both
 *               2001 - 2003  Al Zaharov
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

#include <stdio.h>
#include <time.h>
#include "config.h"

#define IPACLIMIT			INSTALLPATH "/ipaclimit"
#define MAX_PROCFILE_LINE_LENGTH	256
#define SPOOLFILE			"spool"

/** nonstandard type: 64 bit unsigned integer */
typedef unsigned long long int	UINT64;
typedef signed long long int INT64;

/** The internal representation of a timestamp.*/
typedef time_t	timestamp_t;

/** compiler specific attribute to a struct to align
 * on the smallest possible boundary
 */
#define	PACKED	__attribute__((packed))

/** main program's own name */
extern const char *me;

/** the directory with the database.
 *  At least for plain-file and gdbm storage backend - and in any case for
 *  the spool file.
 */
extern const char *datadir;

/** the name of the spool file. */
extern char *spoolfile;

/** local host name */
extern char *hostname;

/** config file name */
extern char conffile[256];

/** flag to indicate if we are within a transaction */
extern int in_transaction;

/** a flag indicating if the storage database backend is opened
 *  in read/write mode. */
extern int storage_opened;

extern int access_opened;

/* the database configuration */
extern char *dbname;
extern char *dbport;
extern char *dbhost;
extern char *dbuser;
extern char *dbpass;

/* verbosity level, 0 - not verbose */
extern int verbose;

/* lock.c */
/** get a lock. Try to exclusevly create the named file. If the file already
 *  exists, read a process id from it and find out if the process still runs.
 *  If not, take over the lock. In case of error, print and error message
 *  do stderr and call exit(1).
 * @param file The file to create or to "take over".
 * @return 0 on success (we got the lock), not 0 if another process has the
 *  lock.
 */
int lock(const char *file);

/** delete a lock created by lock() 
 * @return 0 for success */
int unlock(const char *file);

/* rule.c */
/** a struct for a linked list of rule names with counters. */
struct Srule_type {
/** name of the rule */
	char		name[MAX_RULE_NAME_LENGTH+1];
/** byte count */
	UINT64		bytes;
/** packet count */
	UINT64		pkts;
/** next item in a singly linked list */
	struct Srule_type *next;
};
/** rule type */
typedef struct Srule_type rule_type;


/* linked list of users */
struct Suser_list {
/* login of user */
	char		login[MAX_RULE_NAME_LENGTH+1];
/* user's ip */
	char		ip[MAX_RULE_NAME_LENGTH+1];
/* detailed logs? 0=no, otherwise yes */
	int		detailed;
/* is user paused? */
	int		pause;	
/** next item in a singly linked list */
	struct Suser_list *next;
};
typedef struct Suser_list user_list;

/** create a new instance of rule_type and initialize all data members
 * @return the new rule_type instance
 */
user_list *new_user();

struct Sraw_rule_type {
/** name of the rule */
	char		name[MAX_RULE_NAME_LENGTH+1];
// source network/mask	
	char		snet[MAX_RULE_NAME_LENGTH+1];
// destination network/mask	
	char		dnet[MAX_RULE_NAME_LENGTH+1];
// source port
	char		sport[20];
// destination port	
	char		dport[20];
// protocol
	char		protocol[8];
// interface name	
	char		iface[10];
// (destination)? in/out and many-many more
	char		dest[MAX_RULE_NAME_LENGTH+1];
// target chain (used for custom chains) or target '-j REJECT'/'-j RETURN'/'-j QUEUE'
	char		target[MAX_RULE_NAME_LENGTH+1];
// direction of packet: strictly in/out
	char		direction[4];
	char 		*extension[16];
/** next item in a singly linked list */
	struct Sraw_rule_type *next;
};
/** rule type */
typedef struct Sraw_rule_type raw_rule_type;


/** a struct containing one data record, including all
 *  rule names, counters, a machine name and a time stamp.
 */
struct Sdata_record_type {
/** timestamp of the record */
	timestamp_t	timestamp;
/** first rule of singly linked list of rules */
	rule_type	*firstrule;
/** the name of the machine */
	char 		*machine_name;
};
/** typedef for data_record_type */
typedef struct Sdata_record_type data_record_type;

void free_tree(void **ruletreep);
void free_raw_list(raw_rule_type *data);

raw_rule_type *new_raw_rule();

/** create a new instance of rule_type and initialize all data members
 * @return the new rule_type instance
 */
rule_type *new_rule();
/** compare two rules for use with qsort() by timestamp value
 * @param rule1 pointer to the first rule to be compared
 * @param rule2 pointer to the second rule to be compared
 * @return see qsort()
 */
int rule_compare(const void *rule1, const void *rule2);
/** free all memory used by array of type data_record_type.
 * @param n the number of data_record_type instances the array has
 */
void free_data_record_type_array(data_record_type *data, int n);
/** compare two timestamp_t's for use with qsort() 
 */
int compare_timestamp_t(const void *t1, const void *t2);

/* xmalloc.c */
/** Replacement function for malloc(). In case of allocation error,
 *  print error message on stderr and exit program.
 * @param size The size of the memory block requested
 * @return a pointer to the newly allocated memory block (and never NULL)
 */
void *xmalloc(size_t size);
/** Replacement function for strdup() using xmalloc().
 * @see xmalloc(), strdup(3).
 */
char *xstrdup(const char *);
/** Replacement function for realloc(). In case of allocation error,
 *  print an error message to stderr and exit program.
 * @see realloc(3)
 */
void *xrealloc(void *ptr, size_t size);

/** Wise replacement for calloc()
 * @see 'info libc'
 */
void *xcalloc(size_t count, size_t size);

/* fetchipac.c */
/** print to stdout a list of all timestamps for data records that contain
 *  data that belongs into the given
 *  time frame. Additionally, print, if they exist, the timestamps of the
 *  records just before and the one just after this period. Output is
 *  sorted.
 *
 *  Depending on the setting of the global machine_format_output, print each
 *  line in a human well readable format (0) or in a machine format. The
 *  machine format is defined as follows: The first line contains just a
 *  number which indicates the total number of timestamps following without
 *  the 'just before' and 'just after' ones. 
 *  Each timestamp is a decimal integer
 *  value. Each timestamp goes on a line on its own. Each one is preceeded
 *  with a asteric ('*') and a space (' ') character. The two extra timstamps
 *  are preceeded with the characters "- " (just before) and "+ " (just after),
 *  respectivly.
 * @param tstart The start timestamp. Actual timestamp output begins not before
 *  tstart+1.
 * @param tend The end timestmap. Actual timstamp output may go up to 
 *  tend inclusive.
 * @return 0 on success.
 */
int list_timestamps(timestamp_t tstart, timestamp_t tend, char *);

/** enter batch mode. read commands from stdin and execute them.
 *  output results to stdout.
 *  valid commands are:
 *  quit        -       terminate
 * @return 0 if all commands executed okay, -1 in case of an error.
 *  errors for specific commands are reported on stdout.
 */
int batchmode();

/** print data records in ASCII representation
 *  depending on the value of machine_output_format, the records are printed
 *  machine readable or intended fro humans
 *  the records printed by one call must have the same timestamp!
 * @param f a file descriptor to print to
 * @param n the number of records in dr (may be 0)
 * @param an array of data records with n elements to be printed
 * @param timestamp the common timestamp of all records to be printed
 * @return 0 if okay, 1 on error
 */
int print_records(FILE *f, int n, const data_record_type *dr);

/** put a record into the spool file.
 * @param dr the record to be stored (only one)
 * @return 0 on success
 */
int spool_record(const data_record_type *dr);

/** read records from spool file and put them into the database, truncating
 *  the spool file on success.
 */
void unspool();

/* batch.y */
/** Run the batchmode. Print a prompt, then call yyparse() to run
 * the semantic defined in batch.y. Get the input from stdin.
 * @param in if not NULL, get the input from strem in instead of stdin 
 *  and dont print
 *  a prompt. 
 * @param num If not NULL, store the number of successful finished commands
 *  into this memory location. Also we are reading from the spool file
 *  then and we stop processing on database errors.
 * @return 0 on success, -1 if there was a database related error
 */
int do_batchmode(FILE *in, int *num);

int parse_config(FILE *in);

/**************************************************
* Accounting agents
**************************************************/

/** a struct to define a accounting agents. this struct is used to
 * create a const table acc_agents containing pointers to elements of it in
 * agentstable.c which is automatically generated by configure.
 * the table contains all known accounting agents. the data
 * in this table are the only way programs communicatie with
 * a accounting agents.
 */
struct Sacc_agent_t {
	const char *name;
	int (*init)(int flag);
	int (*set)(rule_type **firstrule, int first);
	int (*read)(rule_type **firstrule);
	int (*check)(void);
};

typedef struct Sacc_agent_t acc_agent_t;

/** current accounting agent (fetchipac.c) */
extern const acc_agent_t *acc_agent;

/** Array of available accounting agents. There is and end marker with a NULL
 * name.
 */
extern const acc_agent_t **acc_agents;

/** Array of pointers to functions returning the interface to accounting
 * agents. In storagetable.c which is automatically generated at make
 * time.
 */
extern const acc_agent_t *(*acc_agent_if[])();

/*
 * Access controlling agents
 */
struct Saccess_agent_t {
	const char *name;
	int (*open)(int flag);
	int (*get_user_list)(user_list **list);
	int (*get_raw_list)(char *ag_name, char *login, raw_rule_type **data);
	double (*get_cash)(char *login_name);
	int (*set_cash)(char *login_name, double cash);
	double (*get_price)(char *rule_name);
	double (*get_kredit)(char *login);
	int (*get_pay_type)(char *rule_name);
	char * (*get_last_paid)(char *service_name);
	int (*set_last_paid)(char *login, char *paid);
	int (*login)(char *login);
	int (*logout)(char *login, double cash);
	int (*close)();
};

typedef struct Saccess_agent_t access_agent_t;

/** current accounting agent (fetchipac.c) */
extern const access_agent_t *access_agent;

/** Array of available accounting agents. There is and end marker with a NULL
 * name.
 */
extern const access_agent_t **access_agents;

/** Array of pointers to functions returning the interface to accounting
 * agents. In storagetable.c which is automatically generated at make
 * time.
 */
extern const access_agent_t *(*access_agent_if[])();


/**************************************************
* STORAGE METHODS				  *
**************************************************/

/** a struct to define a storage method. this struct is used to
 * create a const table storage_methods containing pointers to elements 
 * of it in 
 * storagetable.c which is automatically generated by configure.
 * the table contains all known storage methods. the data
 * in this table are the only way programs communicatie with
 * a storage method backend.
 */
struct Sstorage_method_t {

	/** - each storage method has a unique name. */
	const char *name;

	/** a pointer to a function to open the database. 
	 * This is called once before any other call to the storage
	 * method.
	 * it is guaranteed that the close() function below is called
	 * once after the database access is done. the database is always
	 * closed as soon as possible.
	 * @param flag Only one bit is used (SM_OPEN_READONLY)
	 * @return 0 for sucess, !=0 otherwise.
	 * @see SM_OPEN_READONLY
	 */
	int (*open)(int flag);

	/** a pointer to a function to store a data record 
	 * @return 0 for success, !=0 otherwise.
	 */
	int (*store_record)(const data_record_type *data);

	/** a pointer to a function to list timestamp values.
	 *  The listing is done for a certain time frame. Those timestamps
	 *  are listed whose data records give information about the
	 *  specified time frame. Start and end times are meant to be
	 *  the beginning of the second.
	 *  creates a dynamically allocated array of
	 *  timestamp_t's and makes *data point to it. 
	 * @param start start time. This is exclusive - the first possible
	 *  timestamp listed is (start+1). (Data starts at (start), but the
	 *  first record which may contain data about our time frame is
	 *  recorded at (start+1)).
	 * @param end end time. This is inclusive - the final possible
	 *  timestamp listed is (end). (Data ends at (end-1), but the
	 *  fincal record which may contain data about our time frame is
	 *  recorded at (end)).
	 * @param data a points to a pointer which is set to the array
	 *  created.
	 * @param just_before timestamp before the result.
	 *  if not NULL, points to a timestamp_t which
	 *  is filled with the value of the timestamp just before the
	 *  first element in *data. If there is no such element, it is
	 *  filled with (timestamp_t)-1.
	 * @param just_after timestamp after the result.
	 *  if not NULL, points to a timestamp_t which
	 *  is filled with the value of the timestamp just after the
	 *  final element in *data. If there is no such element, it is
	 *  filled with (timestamp_t)-1.
	 * @return the
	 *  number of timestamps in the array. returns -1 in case of
	 *  error.
	 */
	int (*list_timestamps)(timestamp_t start, timestamp_t end,
			timestamp_t **data, timestamp_t *just_before,
			timestamp_t *just_after, char *);

	/** - a function to retrieve actual data records from a given 
	 * time interval. if timestamp_e is NULL or equal to timestamp_s
         * only the record for that timestamp is returned (as get_record of
         * older versions of ipac did). Otherwise records for all timestamps
         * between and inclusive timestamp_s and timestamp_e are returned.
	 * creates an array of data_record_type's and sets *data to
	 * point to it. The array and all data members are dynamically
	 * allocated and need to be freed by the caller. (The function
	 * free_data_record_type_array does a great job doing this.)
	 * if the number of records found is 0 (no data), no memory is
	 * allocated.
	 * @return the number of records returned (may be 0 if there is
	 * no such record), or -1 in case of error. 
	 */
	int (*get_records)(timestamp_t timestamp_s, timestamp_t timestamp_e,
			data_record_type **data, char *filter);

	/** - a function to retrieve summary from a given time interval
	 */
	int (*get_summary)(timestamp_t timestamp_s, timestamp_t timestamp_e,
			data_record_type **data, char *filter);

	/** pointer to a function to delete a record.
	 * Deletes the record(s) specified by timestamp.
	 * @param timestamp the timestamp of the record(s) to delete.
	 * @return 0 for success, !=0 otherwise.
	 */
	int (*delete_record)(timestamp_t timestamp);

	/** - a function to close, called once before exit 
	 * of program or after one transaction is finished
	 */
	void (*close)();

};
/** typedef for storage_method_t */
typedef struct Sstorage_method_t storage_method_t;

/** current storage method (fetchipac.c) */
extern const storage_method_t *storage_method;

/** flags to the open() functions in storage methods */
/*@{*/
/** if opened readonly, the storage backend may open all files read only.
 */
#define SM_OPEN_READONLY	1
/*@}*/

/** Array of available storage methods. There is and end marker with a NULL
 * name.
 */
extern const storage_method_t **storage_methods;


/** Array of pointers to functions returning the interface to storage
 * methodPs. In storagetable.c which is automatically generated at make
 * time.
 */
extern const storage_method_t *(*storage_method_if[])();


#endif
