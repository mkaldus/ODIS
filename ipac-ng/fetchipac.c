/*
 *
 * $Id: fetchipac.c,v 1.22 2009/08/02 13:49:41 mdw21 Exp $
 *
 * Fetch IP accounting stats
 * Copyright (C) 1997 - 2000 Moritz Both
 *           (C) 2001 - 2003 Al Zakharov
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
 * Current developer and maintainer can be reached via kaiser13@mail2000.ru
 *
 */

#include <string.h>
#include <fnmatch.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <search.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include "config.h"
#include <assert.h>
#include "ipac.h"

int		dropzero = 0;

int		verbose = 0;
/** name of the program */
const char 	*me;

/** the directory with the database.
 *  At least for plain-file and gdbm storage backend - and in any case for
 *  the spool file.
 */
const char	*datadir=ACCTDIR;

char		*spoolfile;

/** name of local host. */
char 		*hostname;

/** name of config file. */
char		conffile[256];

/** the table of storage methods */
const storage_method_t **storage_methods;

/** the current storage method */
const storage_method_t *storage_method;

/** the table of accounting agents */
const acc_agent_t **acc_agents;

/** the current accounting agent */
const acc_agent_t *acc_agent;

const access_agent_t **access_agents;
const access_agent_t *access_agent;


/** flag for output format. 0=user readable,
 *  1=for machine (ipacsum) */
int		machine_output_format = 0;
/** flag indicating if SIGALRM closed the databases */
int		db_closed_by_timer;

int in_transaction;

int storage_opened = 0;

int access_opened = 1;

char *storage_method_name = NULL;
char *acc_agent_name = DEFAULT_AGENT;
char *access_agent_name = DEFAULT_ACCESS;
char *authhost = NULL;
char *dbhost = NULL;
char *dbname = NULL;
char *dbport = NULL;
char *dbuser = NULL;
char *dbpass = NULL;
int slogin = 0;
char *ahost = NULL;

static const char usage_message_first[] =
"fetchipac Version " VERSION " - Usage:\n"
"fetchipac [options]\n"
"options are:\n"
"-S|--start\tinitial accounting setup: insert rules and chains\n"
"-C|--config FILE\t specify config file to use\n"
"-b|--batch\texecute commands which are fed via standard input\n"
"-H|--hostname\thostname to work with\n"
	"\t\tif not specified, fetchs with hostname() or hostname from config\n"
	"\t\treports are generated for specified host\n\t\t\tor for all hosts,"
	" if hostname is not specified\n"
"-f|--filter\tsimple filter. show only *<filter expresion>* rules\n"
"-d|--directory DIR\n"
	"\t\tspecify data directory DIR\n"
"-h|--help\tprint this help text\n"
"-m|--machine-output-format\n"
	"\t\toutput data in easily machine parsable format instead of\n"
	"\t\t easily human readable format\n"
"-r|--records\taccept timestamps on stdin, print corresponding records\n"
	"\t\t on stdout\n"
"-s|--storage-method METHOD\n"
	"\t\tuse METHOD as storage method. METHOD can be one of:\n"
	"\t\t ";
static const char usage_message_second[] = "\n"
	"\t\t Default is " DEFAULT_STORAGE "\n"
"-t|--timestamps [START][,END]\n"
	"\t\tlist timestamps. If given, start with timestamps START and\n"
	"\t\t end with timestamp END\n"
"-u|--sum {START][,END]\n"
	"\t\tprint summary for given timeframe\n"
"-R|--list-raw\tlist raw accounting rules\n"
"-v|--verbose\tadd one level of verbosity\n"
"See fetchipac(8) for further information.\n";

// check existence of chains and rules in kernel
// try to check whether rules in kernel are good
// return 0 in case of all ok
int
check_rules(void)
{
	acc_agent->init(0);
	return acc_agent->check();
}

int
list_raw(void)
{
	raw_rule_type *r;
	int i;

	if(access_agent->get_raw_list("", "", &r)) {
		fprintf(stderr, "access error\n");
		access_agent->close();
		return 1;
	}
	printf("rule name            | destination   | iface | proto | "
			"source              | destination         | direction | extensions\n");
	printf("------------------------------------------------------------------"
			"------------------------------------------------------\n");
	while(r) {
		printf("%-20s | %-13s | %-5s | %-5s | %-18s %s | %-18s %s | %-9s | %-8s",r->name,
			r->dest,r->iface,r->protocol,r->snet,r->sport,r->dnet,
			r->dport,r->direction,r->target);
		for (i=0;i<8;i++) {
			if (r->extension[i])
				printf(" %-8s ", r->extension[i]);
		}
		printf("\n");
		r = r->next;
	}
	return 0;
}

int
setup_access(int first)
{
	rule_type *tmp;

	if(acc_agent->init(0)) {
		perror("Failed to initialize accounting agent, "
			"aborting operations\n");
		return 1;
	}
	if(acc_agent->set(&tmp, first)) {
		perror("Failed to setup accounting agent, "
			"aborting operations\n");
		return 1;
	}
	return 0;
}

int
setup_agents(void)
{
	return setup_access(1);
}

/** print the usage message */
void
usage()
{
	const storage_method_t **p;

	printf(usage_message_first);
	for (p=storage_methods; *p != NULL; p++) {
		printf("%s%s", (*p)->name, (p[1] != NULL ? ", ": ""));
	}
	printf(usage_message_second);
}

/** set the hostname variable to the correct local host name. */
static void set_hostname()
{
	char hname[256];
	
	if (!hostname) {
		if (gethostname(hname, 256) != 0) {
			strcpy(hname, "(unknown host)");
			fprintf(stderr, "%s warning: cant get hostname, "
				"using '%s': %s\n",
				me, hname, strerror(errno));
		} else
			hostname = xstrdup(hname);
	}
}

/** create array storage_methods
 * @see storage_methods
 */
void
create_storage_methods()
{
	int i;
	const storage_method_t **p;
	const storage_method_t *(**pt)();

	for (i=0, pt=storage_method_if; *pt!=NULL; pt++, i++)
		;
	storage_methods = (const storage_method_t **)xmalloc((i+1) *
			sizeof(storage_method_t *));
	for (p = storage_methods, pt = storage_method_if; *pt!=NULL; p++, pt++)
		*p = (*pt)();
	*p = NULL;
}

/** create array acc_agents
 * @see acc_agents
 */
void create_acc_agents()
{
	int i;
	const acc_agent_t **p;
	const acc_agent_t *(**pt)();

	for (i=0, pt=acc_agent_if; *pt!=NULL; pt++, i++)
		;
	acc_agents = (const acc_agent_t **)xmalloc((i+1) *
			sizeof(acc_agent_t *));
	for (p = acc_agents, pt = acc_agent_if; *pt!=NULL; p++, pt++)
		*p = (*pt)();
	*p = NULL;
}

/** create array acc_agents
 * @see access_agents
 */
void create_access_agents()
{
	int i;
	const access_agent_t **p;
	const access_agent_t *(**pt)();

	for (i=0, pt=access_agent_if; *pt!=NULL; pt++, i++)
		;
	access_agents = (const access_agent_t **)xmalloc((i+1) *
			sizeof(access_agent_t *));
	for (p = access_agents, pt = access_agent_if; *pt!=NULL; p++, pt++)
		*p = (*pt)();
	*p = NULL;
}

void free_tree(void **ruletreep)
{
	/* The tree should be deleted here...
	 * Since fetchipac exists anyway, we don't NEED this.
	 */
}

/** make a nice ASCII string from a timestamp_t
 * s must be an array with at least 30 chars
 */
static void nice_time(timestamp_t t, char *s)
{
	struct tm *tmp;

	tmp = localtime(&t);

	strftime(s, 29, "%c", tmp);
}

int list_timestamps(timestamp_t tstart, timestamp_t tend, char *ahost)
{
	timestamp_t *tlist, *t, before, after;
	int n, i;
	char s[30];

	if (!storage_opened) {
		storage_method->open(SM_OPEN_READONLY);
		n = storage_method->list_timestamps(tstart, tend, &tlist,
			&before, &after, ahost);
		storage_method->close();
	} else
		n = storage_method->list_timestamps(tstart, tend, &tlist,
			&before, &after, ahost);
	
	if (n > 0) {
		printf(machine_output_format ? "%d\n"
				: "number of timestamps found: %d\n", n);
		if (before != (timestamp_t)-1) {
			if (machine_output_format)
				printf("- %lu\n", before);
			else {
				nice_time(before, s);
				printf("%12lu (%s) (final timestamp before "
						"start time)\n", before, s);
			}
		}
		for (i=0, t=tlist; i<n; i++, t++) {
			if (machine_output_format)
				printf("* %lu\n", *t);
			else
			{
				nice_time(*t, s);
				printf("%12lu (%s) ", *t, s);
				if (i%2 == 1)
					printf("\n");
			}
		}
		if (machine_output_format == 0)
			printf("\n");
		if (after != (timestamp_t)-1)
		{
			if (machine_output_format)
				printf("+ %lu\n", after);
			else
			{
				nice_time(after, s);
				printf("%12lu (%s) (first timestamp after "
						"end time)\n", after, s);
			}
		}
	} else
		printf(machine_output_format ? "0\n"
				: "number of timestamps found: 0\n");
	if (n > 0)
		free(tlist);
	return n>-1 ? 0 : 1;
}

/* print a record on file descriptor f */
int
print_records(FILE *f, int n, const data_record_type *dr)
{
	char buf[256];
	rule_type *r;
	int i;

	if (n < 0) {
		fprintf(f, "ERROR\n");
		return 1;
	}
	
	for (i=0; i<n; i++, dr++) {
		fprintf(f, "%s%lu ", machine_output_format ? "ADD\n":"timstamp: ",
			  dr->timestamp);
		if (machine_output_format == 0) {
			nice_time(dr->timestamp, buf);
			fprintf(f, "(%s) ", buf);
		}
		fprintf(f, "%s1\n", machine_output_format ? "":
			"number of records: ");
		if (machine_output_format == 0 && n>1)
			fprintf(f, "  record number: 1\n");
		fprintf(f, machine_output_format ?
				"( %s\n" : "    machine name: %s\n",
				/* FIXME: at the moment it's useless to
				          print the machine name returned
				dr->machine_name
				*/
				(ahost != NULL) ? ahost : "");
		for (r = dr->firstrule; r != NULL; r=r->next)
			fprintf(f, machine_output_format ?
				"%llu %llu |%s|\n"
				: "    bytes %14llu pkts %12llu %s\n",
				r->bytes, r->pkts, r->name);
		fprintf(f, "%s\n", machine_output_format ? ")" : "");
		printf("\n");
	}
	return 0;
}

/* list record data of timestamps on standard input */
int list_records(char *filter)
{
	timestamp_t timestamp_b, timestamp_e, *t, *tlist = NULL;
	data_record_type *dr = NULL;
	char buf[256], *cp;
	int n = 0, i, cnt;

	if (!storage_opened)
		storage_method->open(SM_OPEN_READONLY);

	while(fgets(buf, 256, stdin) != NULL) {
		cp = buf;
		if (*cp == '+' || *cp == '*' || *cp == '-')
			cp++;
		while (*cp!=0 && *cp==' ')
			cp++;
		timestamp_b = strtoul(cp, &cp, 0);
		if (*cp == '-') { //we also have an end timestamp
			cp++;
			timestamp_e = strtoul(cp, NULL, 10);
		}
		else
			timestamp_e = 0;

		if (timestamp_e 
			&& (!strcmp(storage_method->name, "postgre") ||
			    !strcmp(storage_method->name, "mysql")
			)) {
			/* for postgres/mysql storage and query for a timestamp range
			   do some memory optimizations */
			cnt = storage_method->list_timestamps(timestamp_b, timestamp_e, &tlist,
								NULL, NULL, NULL);
			
			for (i=0, t=tlist; i<cnt; i++, t++) {
				n = storage_method->get_records(*t, 0, &dr, filter);
				print_records(stdout, n, dr);

			}
			if (tlist) {
				free (tlist);
				tlist = NULL;
			}
		} else {
			/* all other storage methodes do it the default way */
			n = storage_method->get_records(timestamp_b, timestamp_e, &dr, filter);
			print_records(stdout, n, dr);
		}
		
		/* free memory
		   FIXME: in the future all backends should clear it's data at store_close() time */
		if (strcmp(storage_method->name, "postgre") 
		 && strcmp(storage_method->name, "sqlite") 
		 && strcmp(storage_method->name, "mysql") 
		 && (n>0))
			/* only for storage backends that don't already do free their own data 
			   we have to do it now */
			free_data_record_type_array(dr, n);
		
	}
	storage_method->close();
	fflush(stdout);
	return 0;
}

int print_summary(timestamp_t tstart, timestamp_t tend,
			char *ahost, char *filter)
{
	data_record_type *dr;
	int n;

	storage_method->open(SM_OPEN_READONLY);
	n = storage_method->get_summary(tstart, tend, &dr, filter);
	print_records(stdout, n, dr);

	if (n > 0)
		free_data_record_type_array(dr, n);

	storage_method->close();
	fflush(stdout);
	return 0;
}

/* spool a record. */
int spool_record(const data_record_type *dr)
{
	FILE *f;
	char *ahost_saved;
	int mof;
	int ret;

	f = fopen(spoolfile, "a");
	if (f == NULL) {
		fprintf(stderr, "%s: cant open spool file \"%s\" - data lost: "
				"%s\n", me, spoolfile, strerror(errno));
		return 1;
	}

	mof = machine_output_format;
	machine_output_format = 1;
	/* we have to use the ahost - see storage/postgre for details why
	   the hostname in the rules itself is ignored */ 
	ahost_saved = ahost;
	ahost = dr->machine_name;
	ret = 0;
	if (print_records(f, 1, dr) != 0) {
		fprintf(stderr, "%s: cant write data record to spool file \""
				"%s\", data lost: %s\n", me, spoolfile,
				strerror(errno));
		ret = 1;
	}
	fputs("\n", f);
	fclose(f);
	ahost = ahost_saved;
	machine_output_format = mof;
	return ret;
}

/* read spool file, write to database backend */
void unspool()
{
	FILE *f, *newf;
	struct stat stat_buf;
	int num;
	char line[256];		/* to read a line */
	char spoolfile_new[PATH_MAX];

	if (stat(spoolfile, &stat_buf) != 0)
		return;	/* file does not exist - very well */
	if (stat_buf.st_size == 0)
		return; /* file is empty - very well, too */

	f = fopen(spoolfile, "r+");
	if (f == NULL) {
		fprintf(stderr, "%s: cant open spool file \"%s\": %s\n",
				me, spoolfile, strerror(errno));
		return;
	}

	if (do_batchmode(f, &num) != 0) {
		/* error on adding records. */
		if (num > 0) {
			/* we need to rewrite the spool
			 * file, starting at the first failed record.
			 */
			if (fseek(f, 0, SEEK_SET) != 0) {
				fprintf(stderr, "%s: rewriting spool file: "
						"cant seek: %s\n", me,
						strerror(errno));
				/* what now... just leave the spool file
				 * untouched.
				 */
				fclose(f);
				return;
			}
			/* skip all records we dont want. */
			while(num > 0 && fgets(line, 256, f) != NULL) {
				if (strncasecmp(line, "ADD", 3) == 0)
					num--;
				if (strncasecmp(line, "BILL", 4) == 0)
					num--;
			}
			while(fgets(line, 256, f) != NULL) {
				if (strncasecmp(line, "ADD", 3) == 0)
					break;
				if (strncasecmp(line, "BILL", 4) == 0)
					break;
			}
			/* we now have the first line we want to keep */
			strcpy(spoolfile_new, spoolfile);
			strcat(spoolfile_new, ".new");
			newf = fopen(spoolfile_new, "w");
			if (newf == NULL) {
				fprintf(stderr, "%s: cant open new spool file "
						"\"%s\": %s\n", me,
						spoolfile_new,
						strerror(errno));
				fclose(f);
				return;
			}
			do {
				if (fputs(line, newf) == EOF) {
					fprintf(stderr, "%s: cant write to file"
						"\"%s\": %s\n", me,
						spoolfile_new,
						strerror(errno));
					fclose(newf);
					fclose(f);
					return;
				}
			} while(fgets(line, 256, f) != NULL);
			if (ferror(f)) {
				fprintf(stderr, "%s: error reading from spool "
						"file: %s", me,
						strerror(errno));
				fclose(f);
				fclose(newf);
				return;
			}
			fclose(f);
			fflush(newf);
			if (ferror(newf)) {
				fprintf(stderr, "%s: error writing to new spool"
						" file: %s", me,
						strerror(errno));
				fclose(newf);
				return;
			}
			fclose(newf);
			if (rename(spoolfile_new, spoolfile) != 0) {
				fprintf(stderr, "%s: error renaming \"%s\" to "
						"\"%s\": %s\n", me,
						spoolfile_new, spoolfile,
						strerror(errno));
			}
		}
	} else {
		if (unlink(spoolfile) != 0)
			fprintf(stderr, "%s: cant unlink \"%s\": %s - this "
					"might result in corrupted data\n",
					me, spoolfile, strerror(errno));
	}
}

/** enter batch mode. read commands from stdin and execute them.
 *  output results to stdout.
 *  valid commands are:
 *  quit	-	terminate
 * @return 0 if all commands executed okay, -1 in case of an error.
 *  errors for specific commands are reported on stdout.
 */
int batchmode()
{
	machine_output_format = 1;
	return do_batchmode(NULL, NULL);
}

/** fetchipac normally fetches data from the kernel. It can also list
 *  data from the database.
 */
int main(int argc, char **argv)
{
	rule_type *firstrule = NULL;

	int c;
	timestamp_t t, tstart=0, tend=0;
	data_record_type data_record;
	int mode;
	char *cp;
	const storage_method_t **smp;
	const acc_agent_t **aap;
	const access_agent_t **acp;
	int record_stored;		/* 1 if a record could be stored */
	char *filter=NULL;

	FILE *configa;

	static struct option long_options[] = {
		{ "agent",	    required_argument,	NULL,	'a'	},
		{ "config",	    required_argument,	NULL,	'C'	},
		{ "filter",	    required_argument,	NULL,	'f'	},
		{ "start",	    no_argument,	NULL,	'S'	},
		{ "list-raw",       no_argument,	NULL,	'R'	},
		{ "ahost",	    required_argument,  NULL,   'H'     },
		{ "batch",	    no_argument,	NULL,	'b'	},
		{ "directory",	    required_argument,	NULL,	'd'	},
		{ "help",	    no_argument,	NULL,	'h'	},
		{ "machine-output-format", no_argument,	NULL,	'm'	},
		{ "records",	    optional_argument,	NULL,	'r'	},
		{ "storage-method", required_argument,	NULL,	's'	},
		{ "timestamps",	    optional_argument,	NULL,	't'	},
		{ "verbose",	    no_argument,	NULL,	'v'	},
		{ "version",	    no_argument,	NULL,	'h'	},
		{ "sum",	    optional_argument,	NULL,	'u'	},
		{ NULL,		    0,			NULL,	0	}
	};

	me = argv[0];
	mode = 0;	/* fetch data */
	strncpy(conffile, CONFFILE, sizeof(conffile)-1); // default config

	/* create array storage_methods */
	create_storage_methods();
	create_acc_agents();
	create_access_agents();

	/* parse command line */
	while(1)
	{
		c = getopt_long(argc, argv, "a:L:O:C:f:SRUH:bd:vhmu::r::c:s:t::e",
				long_options, NULL);
		if (c==EOF)
			break;
		switch(c)
		{
			case 'a':
				access_agent_name = optarg;
				break;
			case 'b':
				mode = 3; /* batch mode */
				break;
			case 'S':
				mode = 5;
				break;
			case 'H':
				hostname = xstrdup(optarg);
				ahost = xstrdup(optarg);
				break;
			case 'f':
				filter = xstrdup(optarg);
				break;
			case 'C':
				strncpy(conffile, optarg, sizeof(conffile)-1);
				break;
			case 'R':
				mode = 4;
				break;
			case 'd':
				datadir = optarg;
				break;
			case 'h':
				usage();
				exit(1);
			case 'm':
				machine_output_format = 1;
				break;
			case 'v':
				verbose++;
				break;
			case 'r':
				mode = 2;
				break;
			case 's':
				storage_method_name = optarg;
				break;
			case 't':
				mode = 1; /* list timestamps */
				if (optarg != NULL) {
					tstart = strtoul(optarg, &cp, 0);
					if (*cp == ',')
						tend=strtoul(++cp, NULL, 0);
					else
						tend = time(NULL);
				} else {
					tstart = 0;
					tend = time(NULL);
				}
				break;
			case 'u':
				mode = 10; /* get summary */
				if (optarg != NULL) {
					tstart = strtoul(optarg, &cp, 0);
					if (*cp == ',')
						tend = strtoul(++cp, NULL, 0);
					else
						tend = time(NULL);
				} else {
					tstart = 0;
					tend = time(NULL);
				}
				break;
			case '?':
				fprintf(stderr, "%s: unknown option\n",	me);
				exit(1);
		}
	}

	configa = fopen(conffile, "r");
	if (configa != NULL) {
		parse_config(configa);
	} else {
		fprintf(stderr, "error opening config file '%s': %s\n", conffile, strerror (errno));
		return 2;
	}
	fclose(configa);
	set_hostname();

	/* find storage method */
	for (smp = storage_methods; *smp != NULL; smp++)
	{
		if (strcasecmp((*smp)->name, storage_method_name) == 0)
			break;
	}
	if (*smp == NULL) {
		fprintf(stderr, "%s: unknown storage method \"%s\" "
				"(not compiled in?)\n", me,storage_method_name);
		exit(1);
	}
	storage_method = *smp;

	/* find accounting agent */
	for (aap = acc_agents; *aap != NULL; aap++)
	{
		if (strcasecmp((*aap)->name, acc_agent_name) == 0)
			break;
	}

	if (*aap == NULL) {
		fprintf(stderr, "%s: unknown accounting agent \"%s\" "
				"(not compiled in?)\n", me,acc_agent_name);
		exit(1);
	}
	acc_agent = *aap;

	/* find access agent */
	for (acp = access_agents; *acp != NULL; acp++) {
		if (strcasecmp((*acp)->name, access_agent_name) == 0)
			break;
	}
	if (*acp == NULL) {
		fprintf(stderr, "%s: unknown access agent \"%s\" "
				"(not compiled in?)\n", me, access_agent_name);
		exit(1);
	}
	access_agent = *acp;


	if (access_agent->open(0)) {
		fprintf(stderr, "%s: error while opening access database\n", me);
		access_opened = 0;
		fprintf(stderr, "cant operate while database access is absent\n");
		return 1;
	}
	spoolfile = xmalloc(strlen(datadir) + sizeof(SPOOLFILE) + 10);
	sprintf(spoolfile, "%s/" SPOOLFILE, datadir);

	/* the normal mode is 0. If another mode is set, we do what has
	 * to be done here and leave main(). the normal fetch comes below
	 * this switch statement. you are not expected to like this
	 * program structure
	 */
	switch(mode)
	{
		case 1:
			return list_timestamps(tstart, tend, ahost);
		case 2:
			return list_records(filter);
		case 3:
			return batchmode();
		case 4:
			return list_raw();
		case 5:
			return setup_agents();
		case 10:
			return print_summary(tstart, tend, ahost, filter);
	}

// fetch data
	if (acc_agent->init(0)) {
		fprintf(stderr, "Error while initializing accounting agent\n");
		return 1;
	}
	if (check_rules()) {
		fprintf(stderr, "ipac-ng chains or rules corrupted, fix this "
				"with fetchipac -S\n");
		return 1;
	}

	if (lock(LOCKFILE) == 0) {
		struct stat *buf = NULL;

		buf=xcalloc(sizeof(struct stat), 1);
		storage_opened = 0;
		if (storage_method->open(0) != 0) {
			fprintf(stderr, "%s: storage reports error on open, "
					"switching to spool mode\n", me);
		} else
			storage_opened = 1;

		if (!stat(RECONFLAG, buf))
			if (buf->st_size>0) {
				mode=9;
				truncate(RECONFLAG, 0);
			}
		free(buf);
		time(&t);
		// FIXME:
		// Ugly hack to avoid some gdbm storage troubles :(
		// Will be removed together with gdbm storage
		// No, it will not be fixed soon %). only in 2.x :(
/*
		tmp = 1;
		while (tmp>0) {
			if (!storage_opened)
				tmp = 0;// storage closed? nothing to do, just spool
			else
				tmp = storage_method->list_timestamps(t, t, &tlist,
						&before, &after);
			if (tmp>0) t++;
		}
*/
		if (acc_agent->read(&firstrule) == 0) {
			data_record.timestamp = t;
			data_record.firstrule = firstrule;
			data_record.machine_name = hostname;
			record_stored = 0;

			if (dropzero) {
				rule_type *rule1 = firstrule;
				rule_type *rule2 = firstrule;
				
				while (rule1) {
					if (rule1->pkts==0)
						rule2->next=rule1->next;
					else
						rule2=rule1;
					rule1=rule1->next;
				}
			}
			
			if (storage_opened) {
				if (storage_method->store_record(&data_record) == 0)
					record_stored = 1;
				else
					fprintf(stderr, "%s: storage reports error on store record\n", me);
			}

			/* if our data could not be stored for some reason,
			 * we put it in ASCII representation into a spool
			 * file.
			 */
			if (record_stored == 0)
				spool_record(&data_record);
		}

		/* feed previously spooled records into the database. */
		if (storage_opened) {
			unspool();
			storage_method->close();
		}

		unlock(LOCKFILE);
	}
	if (access_opened)
		access_agent->close();
	return 0;
}
