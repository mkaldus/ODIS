/* $Id: iptables.c,v 1.10 2011/09/25 23:12:24 smsoft Exp $
 * ipac-ng v.1.34 
 * Part of this code taken from iptables 1.4.9.1
 */

/* Code to take an iptables-style command line and do it. */

/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 * (C) 2000-2002 by the netfilter coreteam <coreteam@netfilter.org>:
 * 		    Paul 'Rusty' Russell <rusty@rustcorp.com.au>
 * 		    Marc Boucher <marc+nf@mbsi.ca>
 * 		    James Morris <jmorris@intercode.com.au>
 * 		    Harald Welte <laforge@gnumonks.org>
 * 		    Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <getopt.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <iptables.h>
#include <xtables.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <search.h>
#include "ipac.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGAGIGA 0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_NOTARGET	0x0020
#define FMT_VIA		0x0040
#define FMT_NONEWLINE	0x0080
#define FMT_LINENUMBERS 0x0100

#define FMT_PRINT_RULE (FMT_NOCOUNTS | FMT_OPTIONS | FMT_VIA \
			| FMT_NUMERIC | FMT_NOTABLE)
#define FMT(tab,notab) ((format) & FMT_NOTABLE ? (notab) : (tab))

#if XTABLES_VERSION_CODE > 5
#define IPT_ALIGN XT_ALIGN
#endif

static struct option original_opts[] = {
	{.name = "append",        .has_arg = 1, .val = 'A'},
	{.name = "delete",        .has_arg = 1, .val = 'D'},
	{.name = "insert",        .has_arg = 1, .val = 'I'},
	{.name = "replace",       .has_arg = 1, .val = 'R'},
	{.name = "list",          .has_arg = 2, .val = 'L'},
	{.name = "list-rules",    .has_arg = 2, .val = 'S'},
	{.name = "flush",         .has_arg = 2, .val = 'F'},
	{.name = "zero",          .has_arg = 2, .val = 'Z'},
	{.name = "new-chain",     .has_arg = 1, .val = 'N'},
	{.name = "delete-chain",  .has_arg = 2, .val = 'X'},
	{.name = "rename-chain",  .has_arg = 1, .val = 'E'},
	{.name = "policy",        .has_arg = 1, .val = 'P'},
	{.name = "source",        .has_arg = 1, .val = 's'},
	{.name = "destination",   .has_arg = 1, .val = 'd'},
	{.name = "src",           .has_arg = 1, .val = 's'}, /* synonym */
	{.name = "dst",           .has_arg = 1, .val = 'd'}, /* synonym */
	{.name = "protocol",      .has_arg = 1, .val = 'p'},
	{.name = "in-interface",  .has_arg = 1, .val = 'i'},
	{.name = "jump",          .has_arg = 1, .val = 'j'},
	{.name = "table",         .has_arg = 1, .val = 't'},
	{.name = "match",         .has_arg = 1, .val = 'm'},
	{.name = "numeric",       .has_arg = 0, .val = 'n'},
	{.name = "out-interface", .has_arg = 1, .val = 'o'},
	{.name = "verbose",       .has_arg = 0, .val = 'v'},
	{.name = "exact",         .has_arg = 0, .val = 'x'},
	{.name = "fragments",     .has_arg = 0, .val = 'f'},
	{.name = "version",       .has_arg = 0, .val = 'V'},
	{.name = "help",          .has_arg = 2, .val = 'h'},
	{.name = "line-numbers",  .has_arg = 0, .val = '0'},
	{.name = "modprobe",      .has_arg = 1, .val = 'M'},
	{.name = "set-counters",  .has_arg = 1, .val = 'c'},
	{.name = "goto",          .has_arg = 1, .val = 'g'},
	{NULL},
};

/* we need this for iptables-restore.  iptables-restore.c sets line to the
 * current line of the input file, in order  to give a more precise error
 * message.  iptables itself doesn't need this, so it is initialized to the
 * magic number of -1 */

void iptables_exit_error(enum xtables_exittype status, const char *msg, ...) __attribute__((noreturn, format(printf,2,3)));

struct xtables_globals iptables_globals = {
	.option_offset = 0,
	.program_version = IPTABLES_VERSION,
	.opts = original_opts,
	.orig_opts = original_opts,
	.exit_err = iptables_exit_error,
};


#define opts iptables_globals.opts
#define prog_name iptables_globals.program_name
#define prog_vers iptables_globals.program_version
#define global_option_offset iptables_globals.option_offset

/** structure for run file (rule file) */
struct runfile_line_type {
	char *line;
	struct runfile_line_type *next;
};

static struct iptc_handle *handle;

/* plain file ipac interface entries */
int iptables_ipac_init(int flag);
int iptables_ipac_set(rule_type **firstrule, int first);
int iptables_ipac_read(rule_type **firstrule);
int iptables_ipac_check(void);

static const acc_agent_t interface_entry = {
	"iptables",
	iptables_ipac_init,
	iptables_ipac_set,
	iptables_ipac_read,
	iptables_ipac_check,
};

const acc_agent_t *ipac_ag_interface_iptables() {
	return &interface_entry;
}

static const char *
proto_to_name(u_int8_t proto, int nolookup)
{
	unsigned int i;

	if (proto && !nolookup) {
		struct protoent *pent = getprotobynumber(proto);
		if (pent)
			return pent->p_name;
	}

	for (i = 0; xtables_chain_protos[i].name != NULL; ++i)
		if (xtables_chain_protos[i].num == proto)
			return xtables_chain_protos[i].name;

	return NULL;
}

enum {
	IPT_DOTTED_ADDR = 0,
	IPT_DOTTED_MASK
};

static void __attribute__((noreturn))
exit_tryhelp(int status)
{
	fprintf(stderr, "Try `%s -h' or '%s --help' for more information.\n",
			"fetchipac", "fetchipac" );
	xtables_free_opts(1);
	exit(status);
}

void
iptables_exit_error(enum xtables_exittype status, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	fprintf(stderr, "%s v%s: ", "fetchipac", VERSION);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (status == PARAMETER_PROBLEM)
		exit_tryhelp(status);
	if (status == VERSION_PROBLEM)
		fprintf(stderr,
			"Perhaps iptables or your kernel needs to be upgraded.\n");
	/* On error paths, make sure that we don't leak memory */
	xtables_free_opts(1);
	exit(status);
}

/* Christophe Burki wants `-p 6' to imply `-m tcp'.  */
static struct xtables_match *
find_proto(const char *pname, enum xtables_tryload tryload,
	   int nolookup, struct xtables_rule_match **matches)
{
	unsigned int proto;

	if (xtables_strtoui(pname, NULL, &proto, 0, UINT8_MAX)) {
		const char *protoname = proto_to_name(proto, nolookup);

		if (protoname)
			return xtables_find_match(protoname, tryload, matches);
	} else
		return xtables_find_match(pname, tryload, matches);

	return NULL;
}

static void
print_num(u_int64_t number, unsigned int format)
{
	if (format & FMT_KILOMEGAGIGA) {
		if (number > 99999) {
			number = (number + 500) / 1000;
			if (number > 9999) {
				number = (number + 500) / 1000;
				if (number > 9999) {
					number = (number + 500) / 1000;
					if (number > 9999) {
						number = (number + 500) / 1000;
						printf(FMT("%4lluT ","%lluT "), (unsigned long long)number);
					}
					else printf(FMT("%4lluG ","%lluG "), (unsigned long long)number);
				}
				else printf(FMT("%4lluM ","%lluM "), (unsigned long long)number);
			} else
				printf(FMT("%4lluK ","%lluK "), (unsigned long long)number);
		} else
			printf(FMT("%5llu ","%llu "), (unsigned long long)number);
	} else
		printf(FMT("%8llu ","%llu "), (unsigned long long)number);
}

static int
print_match(const struct ipt_entry_match *m,
	    const struct ipt_ip *ip,
	    int numeric)
{
	struct xtables_match *match =
		xtables_find_match(m->u.user.name, XTF_TRY_LOAD, NULL);

	if (match) {
		if (match->print)
			match->print(ip, m, numeric);
		else
			printf("%s ", match->name);
	} else {
		if (m->u.user.name[0])
			printf("UNKNOWN match `%s' ", m->u.user.name);
	}
	/* Don't stop iterating. */
	return 0;
}

/* e is called `fw' here for historical reasons */
static void
print_firewall(const struct ipt_entry *fw,
	       const char *targname,
	       unsigned int num,
	       unsigned int format,
	       struct iptc_handle *const handle)
{
	struct xtables_target *target = NULL;
	const struct ipt_entry_target *t;
	u_int8_t flags;
	char buf[BUFSIZ];

	if (!iptc_is_chain(targname, handle))
		target = xtables_find_target(targname, XTF_TRY_LOAD);
	else
		target = xtables_find_target(IPT_STANDARD_TARGET,
		         XTF_LOAD_MUST_SUCCEED);

	t = ipt_get_target((struct ipt_entry *)fw);
	flags = fw->ip.flags;

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(fw->counters.pcnt, format);
		print_num(fw->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname);

	fputc(fw->ip.invflags & IPT_INV_PROTO ? '!' : ' ', stdout);
	{
		const char *pname = proto_to_name(fw->ip.proto, format&FMT_NUMERIC);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), fw->ip.proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(fw->ip.invflags & IPT_INV_FRAG ? '!' : '-', stdout);
		fputc(flags & IPT_F_FRAG ? 'f' : '-', stdout);
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];

		if (fw->ip.invflags & IPT_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ip.iniface[0] != '\0') {
			strcat(iface, fw->ip.iniface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (fw->ip.invflags & IPT_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ip.outiface[0] != '\0') {
			strcat(iface, fw->ip.outiface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}

	fputc(fw->ip.invflags & IPT_INV_SRCIP ? '!' : ' ', stdout);
	if (fw->ip.smsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf, xtables_ipaddr_to_numeric(&fw->ip.src));
		else
			strcpy(buf, xtables_ipaddr_to_anyname(&fw->ip.src));
		strcat(buf, xtables_ipmask_to_numeric(&fw->ip.smsk));
		printf(FMT("%-19s ","%s "), buf);
	}

	fputc(fw->ip.invflags & IPT_INV_DSTIP ? '!' : ' ', stdout);
	if (fw->ip.dmsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf, xtables_ipaddr_to_numeric(&fw->ip.dst));
		else
			strcpy(buf, xtables_ipaddr_to_anyname(&fw->ip.dst));
		strcat(buf, xtables_ipmask_to_numeric(&fw->ip.dmsk));
		printf(FMT("%-19s ","-> %s"), buf);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

#ifdef IPT_F_GOTO
	if(fw->ip.flags & IPT_F_GOTO)
		printf("[goto] ");
#endif

	IPT_MATCH_ITERATE(fw, print_match, &fw->ip, format & FMT_NUMERIC);

	if (target) {
		if (target->print)
			/* Print the target information. */
			target->print(&fw->ip, t, format & FMT_NUMERIC);
	} else if (t->u.target_size != sizeof(*t))
		printf("[%u bytes of unknown target data] ",
		       (unsigned int)(t->u.target_size - sizeof(*t)));

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static void
print_firewall_line(const struct ipt_entry *fw,
		    struct iptc_handle *const h)
{
	struct ipt_entry_target *t;

	t = ipt_get_target((struct ipt_entry *)fw);
	print_firewall(fw, t->u.user.name, 0, FMT_PRINT_RULE, h);
}

static unsigned char *
make_delete_mask(struct xtables_rule_match *matches,
		 const struct xtables_target *target)
{
	/* Establish mask for comparison */
	unsigned int size;
	struct xtables_rule_match *matchp;
	unsigned char *mask, *mptr;

	size = sizeof(struct ipt_entry);
	for (matchp = matches; matchp; matchp = matchp->next)
		size += IPT_ALIGN(sizeof(struct ipt_entry_match)) + matchp->match->size;

	mask = xtables_calloc(1, size
			 + IPT_ALIGN(sizeof(struct ipt_entry_target))
			 + target->size);

	memset(mask, 0xFF, sizeof(struct ipt_entry));
	mptr = mask + sizeof(struct ipt_entry);

	for (matchp = matches; matchp; matchp = matchp->next) {
		memset(mptr, 0xFF,
		       IPT_ALIGN(sizeof(struct ipt_entry_match))
		       + matchp->match->userspacesize);
		mptr += IPT_ALIGN(sizeof(struct ipt_entry_match)) + matchp->match->size;
	}

	memset(mptr, 0xFF,
	       IPT_ALIGN(sizeof(struct ipt_entry_target))
	       + target->userspacesize);

	return mask;
}

int
for_each_chain(int (*fn)(const ipt_chainlabel, int, struct iptc_handle *),
	       int verbose, int builtinstoo, struct iptc_handle *handle)
{
        int ret = 1;
	const char *chain;
	char *chains;
	unsigned int i, chaincount = 0;

	chain = iptc_first_chain(handle);
	while (chain) {
		chaincount++;
		chain = iptc_next_chain(handle);
        }

	chains = xtables_malloc(sizeof(ipt_chainlabel) * chaincount);
	i = 0;
	chain = iptc_first_chain(handle);
	while (chain) {
		strcpy(chains + i*sizeof(ipt_chainlabel), chain);
		i++;
		chain = iptc_next_chain(handle);
        }

	for (i = 0; i < chaincount; i++) {
		if (!builtinstoo
		    && iptc_builtin(chains + i*sizeof(ipt_chainlabel),
				    handle) == 1)
			continue;
	        ret &= fn(chains + i*sizeof(ipt_chainlabel), verbose, handle);
	}

	free(chains);
        return ret;
}

int
flush_entries(const ipt_chainlabel chain, int verbose,
	      struct iptc_handle *handle)
{
	if (!chain)
		return for_each_chain(flush_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Flushing chain `%s'\n", chain);
	return iptc_flush_entries(chain, handle);
}

int
delete_chain(const ipt_chainlabel chain, int verbose,
	     struct iptc_handle *handle)
{
	if (!chain)
		return for_each_chain(delete_chain, verbose, 0, handle);

	if (verbose)
		fprintf(stdout, "Deleting chain `%s'\n", chain);
	return iptc_delete_chain(chain, handle);
}

static struct ipt_entry *
generate_entry(const struct ipt_entry *fw,
	       struct xtables_rule_match *matches,
	       struct ipt_entry_target *target)
{
	unsigned int size;
	struct xtables_rule_match *matchp;
	struct ipt_entry *e;

	size = sizeof(struct ipt_entry);
	for (matchp = matches; matchp; matchp = matchp->next)
		size += matchp->match->m->u.match_size;

	e = xtables_malloc(size + target->u.target_size);
	*e = *fw;
	e->target_offset = size;
	e->next_offset = size + target->u.target_size;

	size = 0;
	for (matchp = matches; matchp; matchp = matchp->next) {
		memcpy(e->elems + size, matchp->match->m, matchp->match->m->u.match_size);
		size += matchp->match->m->u.match_size;
	}
	memcpy(e->elems + size, target, target->u.target_size);

	return e;
}

//===================================================
static int
tcp_service_to_port(const char *name)
{
	struct servent *service;

	if ((service = getservbyname(name, "tcp")) != NULL)
		return ntohs((unsigned short) service->s_port);

	return -1;
}

static u_int16_t
parse_tcp_port(const char *port)
{
	unsigned int portnum;

	if (xtables_strtoui(port, NULL, &portnum, 0, 65535) ||
	    (portnum = tcp_service_to_port(port)) != -1)
		return (u_int16_t)portnum;
	
	fprintf(stderr, "invalid TCP port/service `%s' specified\n", port);
	exit(1);
}

/* - T.Mohan 5/7/2001
 * parse_tcp_ports() function source from 
 * iptables-1.2.2 file:extensions/ibip6t_tcp.c
 */

static void
parse_tcp_ports(const char *portstring, u_int16_t *ports)
{
	char *buffer;
	char *cp;

	buffer = strdup(portstring);
	if ((cp = strchr(buffer, ':')) == NULL)
		ports[0] = ports[1] = parse_tcp_port(buffer);
	else {
		*cp = '\0';
		cp++;

		ports[0] = buffer[0] ? parse_tcp_port(buffer) : 0;
		ports[1] = cp[0] ? parse_tcp_port(cp) : 0xFFFF;
	}
	free(buffer);
}

static int
udp_service_to_port(const char *name)
{
	struct servent *service;

	if ((service = getservbyname(name, "udp")) != NULL)
		return ntohs((unsigned short) service->s_port);

	return -1;
}

static u_int16_t
parse_udp_port(const char *port)
{
	unsigned int portnum;

	if (xtables_strtoui(port, NULL, &portnum, 0, 65535) ||
	    (portnum = udp_service_to_port(port)) != -1)
		return (u_int16_t)portnum;
	
	fprintf(stderr, "invalid UDP port/service `%s' specified\n", port);
	exit(1);
}

/* - T.Mohan 5/7/2001
 * parse_udp_ports() function source from 
 * iptables-1.2.2 file:extensions/ibip6t_udp.c
 */

static void
parse_udp_ports(const char *portstring, u_int16_t *ports)
{
	char *buffer;
	char *cp;

	buffer = strdup(portstring);
	if ((cp = strchr(buffer, ':')) == NULL)
		ports[0] = ports[1] = parse_udp_port(buffer);
	else {
		*cp = '\0';
		cp++;

		ports[0] = buffer[0] ? parse_udp_port(buffer) : 0;
		ports[1] = cp[0] ? parse_udp_port(cp) : 0xFFFF;
	}
	free(buffer);
}

/** read kernel accounting data in iptables system
 * read from stream f
 * create records with data (packet and data counters) and
 * rule names and store them into instances of rule_type (declared
 * in ipac.h) using rule names from runfile
 * if a rule name is equal to a previously used rule name, add the
 * counters and re-use the old record
 * complain if something is wrong with the data.
 * return 0 for success, 1 otherwise
 */
static int 
read_iptables(struct runfile_line_type *runfile, rule_type **firstrule)
{
	char *cp="\0";
	rule_type *rule, *lastrule;
	rule_type *chain, *lastchain, *firstchain;
	struct runfile_line_type *nextline;
	void *node;
	void *ruletree = NULL;
	void *chaintree = NULL;
	struct ipt_counters *counters = NULL;

	if (handle)
		iptc_commit(handle);	// we need fresh snapshot of the rules

	iptables_ipac_init(0);		// init after commit is a must
	
	/* create the rule_type records in correct order as from 
	 * run file.
	 */
	lastrule = *firstrule = NULL;
	chain = lastchain = firstchain = NULL;
	for (nextline=runfile; nextline!=NULL; nextline=nextline->next) {
		cp = strchr(nextline->line, '|');
		if (cp == 0)
			continue;	/* bad entry */
		rule = new_rule();

		chain = new_rule();

		strncpy(rule->name, cp+1, MAX_RULE_NAME_LENGTH);
		strncpy(chain->name, nextline->line, cp-nextline->line);
		chain->name[cp-nextline->line]='\0';

		node = tsearch(chain, &chaintree, rule_compare);
		if (*(rule_type **)node != chain) {
			free(chain);
			chain=*(rule_type **)node;	// chain is already there
		} else {
			if (lastchain != NULL)
				lastchain->next = chain;
			lastchain = chain;
			if (firstchain == NULL)
				firstchain = chain;
		}
		
		if (rule->name[0] == '%') {
			printf("rule starts with %%: %s\n", rule->name);
			chain->pkts++;
			continue;
		}

		if (verbose > 1) {
			printf("iptc_read_count %s %lld\n", chain->name, chain->pkts);
		}
		counters = iptc_read_counter(chain->name, chain->pkts, handle);
		if (counters) {
			iptc_zero_counter(chain->name, chain->pkts, handle);
			chain->pkts++;
		} else {
		  perror("iptc_read_count failed");
		}

		/* use a binary tree to find rules with same name */
		node = tsearch(rule, &ruletree, rule_compare);
		if (*(rule_type **)node != rule) {
			free(rule);
			rule=*(rule_type **)node;
		} else {
			if (lastrule != NULL)
				lastrule->next = rule;
			lastrule = rule;
			if (*firstrule == NULL)
				*firstrule = rule;
		}
		if (counters) {
			rule->pkts += counters->pcnt;
			rule->bytes += counters->bcnt;
		} else {
			rule->pkts = 0;
			rule->bytes = 0;
		}
	}
	iptc_commit(handle);
	iptables_ipac_init(0);
	free_tree(&ruletree);
	free_tree(&chaintree);
	return 0;
}


// ---------------------------------------------------------------------


/** delete run file (rule file) from memory, freeing dynamically
 *  allocated memory
 */
static void 
destroy_runfile_lines(struct runfile_line_type *lines)
{
	struct runfile_line_type *next;
	while(lines != NULL)
	{
		if (lines->line != NULL)
			free(lines->line);
		next = lines->next;
		free(lines);
		lines = next;
	}
}

//------------------------------------------------------------------
/** read run file (rule file) and store it in memory, using a singly 
 *  linked list of instances of struct runfile_line_type
 *  return the list read or NULL in case of error
 */
static struct runfile_line_type 
*read_runfile()
{
	FILE *frunfile;
	char runfile_line[MAX_RULE_NAME_LENGTH*2], *cp; 
	struct runfile_line_type *result, *lastline, *cur;
	
	int tmp=0;

	frunfile = fopen(RUNFILE, "r");
	if (frunfile == NULL) {
		fprintf(stderr, "%s: cant open run file \"%s\": %s "
				"(fetchipac -S not ran?)\n",
			me, RUNFILE, strerror(errno));
		return NULL;
	}

	result = NULL;
	lastline = NULL;
	while(fgets(runfile_line, MAX_RULE_NAME_LENGTH*2, frunfile) != NULL) {
		tmp++;
		cp = strchr(runfile_line, '\n');
		if (cp)
			*cp = '\0';
		if (*runfile_line == '#')
			continue;

		cur = (struct runfile_line_type *)
				xmalloc(sizeof(struct runfile_line_type));
		cur->line = xstrdup(runfile_line);
		cur->next = NULL;
		if (result == NULL)
			result = cur;
		else 
			lastline->next = cur;
		lastline = cur;
	}
	if (!feof(frunfile)) {
		fprintf(stderr, "%s: reading \"%s\": %s\n",
			me, RUNFILE, strerror(errno));
		fclose(frunfile);
		destroy_runfile_lines(result);
		result = NULL;
	}
	fclose(frunfile);
	return result;
}


static int
check_inverse_type(char* src)
{
	if (src) {
		if (memcmp(src, "!", 1) == 0) {
			int slen = strlen(src);

			//strip the "!"
			memcpy(src, src+1, slen);

			//if all there was, was a `!' after doing the strip,
			// return no inverse and don't complain about it.
			if (slen == 1)
				return 0;

			if (memcmp(src, "!", 1) == 0)
				xtables_error(PARAMETER_PROBLEM,
					   "Multiple `!' flags not allowed");

			return 1;
		}
	}
	return 0;
}

/*
 * Prepare ipt entry for such a funcs as insert, delete, append, replace rule
 *
 */
static int
prepare_entry (raw_rule_type *d, struct ipt_entry **e)
{
	struct ipt_entry fw;
	unsigned int naddrs = 0;
	struct in_addr *addrs = NULL;
	struct xtables_target *target = NULL;
	struct xtables_target *t;
	struct xtables_rule_match *matches = NULL;
	struct xtables_rule_match *matchp;
	struct xtables_match *m;
	size_t size;
	int inverse;
	int c,argc;
	int invert = 0;

	bzero(&fw, sizeof(fw));

	if (verbose>2)
		printf("preparing entry for '%s' chain\n", d->dest);

	if (!strcmp(d->protocol, "all"))
		d->protocol[0]='\0';

	if (d->iface && strlen(d->iface)>1) {
		if ((!strncmp(d->dest+strlen(d->dest)-2, "~o", 2)) ||
				(!strncmp(d->dest+strlen(d->dest)-3, "~fi", 3)) ||
				(!strncmp(d->dest+strlen(d->dest)-4, "~c_o", 4)) ||
			        (!strncmp(d->dest+strlen(d->dest)-5, "~c_fi", 5))) {
			inverse = check_inverse_type(d->iface);
			xtables_parse_interface(d->iface, fw.ip.iniface, fw.ip.iniface_mask);
	                fw.ip.invflags |= (inverse ? IPT_INV_VIA_IN : 0);
			fw.nfcache = NFC_IP_IF_IN;
		} else {
			inverse = check_inverse_type(d->iface);
			xtables_parse_interface(d->iface, fw.ip.outiface, fw.ip.outiface_mask);
	                fw.ip.invflags |= (inverse ? IPT_INV_VIA_OUT : 0);
			fw.nfcache = NFC_IP_IF_OUT;
		}
	} else
		fw.ip.invflags = 0;

	for (matchp = matches; matchp; matchp = matchp->next) {
	  /* XXX: final_match? */
		matchp->match->mflags = 0;
	}

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}
	
	if (!iptc_is_chain(d->dest, handle)) {
		fprintf(stderr, "%s is not a chain\n", d->dest);
		return (1);
	}

	if (strlen(d->snet)>2) {
		if (check_inverse_type(d->snet))
			fw.ip.invflags |= IPT_INV_SRCIP;
		xtables_ipparse_any(d->snet, &addrs, &(fw.ip.smsk), &naddrs);
		if (naddrs>1)
			xtables_error(PARAMETER_PROBLEM, 
				"Incorrect rule: more than 1 source address\n");
		fw.ip.src.s_addr = addrs[0].s_addr;
		fw.nfcache |= NFC_IP_SRC;
	}
	
	if (strlen(d->dnet)>2) {
		if (check_inverse_type(d->dnet))
			fw.ip.invflags |= IPT_INV_DSTIP;
		xtables_ipparse_any(d->dnet, &addrs, &(fw.ip.dmsk), &naddrs);
		if (naddrs>1)
			xtables_error(PARAMETER_PROBLEM, "Incorrect rule: more than 1 "
					    "destination address\n");
		fw.ip.dst.s_addr = addrs[0].s_addr;
		fw.nfcache |= NFC_IP_DST;
	}

	if ((d->sport[0]!='\0' || d->dport[0]!='\0') && d->protocol[0]=='\0')
		xtables_error(PARAMETER_PROBLEM, "Incorrect rule: source or "
		    "destination port specified while protocol is not. sport='%s', dport='%s'\n",
			d->sport, d->dport);
	
	/* Loading target /if any/ */
	target = xtables_find_target(IPT_STANDARD_TARGET, XTF_LOAD_MUST_SUCCEED);
	size = sizeof(struct ipt_entry_target) + target->size;
	target->t = xcalloc(1, size);
	target->t->u.target_size = size;
	strcpy(target->t->u.user.name, d->target);
	if (target->init != NULL) 
		target->init(target->t);

	if(check_inverse_type(d->protocol))
		fw.ip.invflags |= IPT_INV_PROTO;

	if (d->protocol[0] != '\0') {
		fw.ip.proto = xtables_parse_protocol(d->protocol);
		fw.nfcache |= NFC_IP_PROTO;
	}

	if (d->protocol[0] != '\0' && d->protocol[0] != 'i') {
		m = find_proto(d->protocol, XTF_LOAD_MUST_SUCCEED, 0, &matches);

		size = IPT_ALIGN(sizeof(struct ipt_entry_match)) + m->size;
		m->m = xcalloc(size, 1);
		m->m->u.match_size = size;
		strcpy(m->m->u.user.name, m->name);
		m->init(m->m);

		if (d->sport[0]!='\0' || d->dport[0]!='\0') {
			if (!strcmp(d->protocol, "tcp")) {
				struct ipt_tcp *tcpinfo = (struct ipt_tcp *)m->m->data;

				if (d->sport[0]!='\0')
					/* - T.Mohan 5/7/2001 */
					parse_tcp_ports(d->sport, tcpinfo->spts);

				if (d->dport[0]!='\0')
					/* - T.Mohan 5/7/2001 */
					parse_tcp_ports(d->dport, tcpinfo->dpts);
			}

			if (!strcmp(d->protocol, "udp")) {
				struct ipt_udp *udpinfo = 
						(struct ipt_udp *)m->m->data;
				if (d->sport[0]!='\0')
					/* - T.Mohan 5/7/2001 */
					parse_udp_ports(d->sport, udpinfo->spts);

				if (d->dport[0]!='\0')
					/* - T.Mohan 5/7/2001 */
					parse_udp_ports(d->dport, udpinfo->dpts);
			}
		}
	}
	
	if (d->extension[2]) {
		opts = original_opts;
		optind = 0;
		global_option_offset = 0;

		d->extension[0] = xstrdup("fetchipac");
		d->extension[1] = xstrdup("-m");
	
		for (argc=0;d->extension[argc];argc++);
		
		// parse extension
		while ((c = getopt_long(argc, d->extension,"-m:", opts, NULL))!= -1) {
			switch 	(c) {
				case 'm':
					m = xtables_find_match(optarg, XTF_LOAD_MUST_SUCCEED, &matches);
					size = IPT_ALIGN(sizeof(struct ipt_entry_match)) + m->size;
					m->m = xcalloc(1, size);
					m->m->u.match_size = size;
					strcpy(m->m->u.user.name, m->name);
					if (m->init != NULL)
						m->init(m->m);
#if XTABLES_VERSION_CODE > 5
					opts = xtables_merge_options(iptables_globals.orig_opts,
							opts, m->extra_opts, &m->option_offset);
#else
					opts = xtables_merge_options(opts, m->extra_opts, 
							&m->option_offset);
#endif
					break;
				case 1:
					if (optarg[0] == '!' && optarg[1] == '\0') {
						if (invert)
							xtables_error(PARAMETER_PROBLEM,
									"multiple consecutive ! "
									"not allowed");
						invert = TRUE;
						optarg[0] = '\0';
						continue;
					}
					printf("Bad argument `%s'\n", optarg);
					exit(1);

				default: 
				  for (matchp = matches; matchp; matchp = matchp->next) {
				    if (matchp->completed) 
				      continue;
				    if (matchp->match->parse(c - matchp->match->option_offset,
							     d->extension, invert,
							     &matchp->match->mflags,
							     &fw,
							     &matchp->match->m))
						break;
				}
				  break;
			}
		}
	}
	for (matchp = matches; matchp; matchp = matchp->next)
		if (matchp->match->final_check != NULL)
			matchp->match->final_check(matchp->match->mflags);
	
	if (target != NULL && target->final_check != NULL)
		target->final_check(target->tflags);
	*e = generate_entry(&fw, matches, target->t);

	if (!handle) if (!(handle = iptc_init("filter")))
			    xtables_error(PARAMETER_PROBLEM, 
				"iptables: %s\n", iptc_strerror(errno));
			
	return 0;
}

/*
 * Try to insert rule into kernel return 0 in case all right, 1 otherwise
 */
static int
insert_rule(raw_rule_type *d, int rule_num)
{
	struct ipt_entry *e = NULL;
	int ret=1;

	if (prepare_entry(d, &e)!=0)
		return (1);
	if (verbose>1) {
		printf("Inserting rule\n");
		print_firewall_line(e, handle);
	}
	ret &= iptc_insert_entry(d->dest, e, rule_num, handle);
	free(e);
	return ret;
}

static int
append_rule (raw_rule_type *d)
{
	struct ipt_entry *e = NULL;
	
	if (prepare_entry(d, &e)!=0)
		return (1);
	
	if (verbose>1) {
		printf("Appending rule to chain '%s'\n", d->dest);
		print_firewall_line(e, handle);
	}
	if (!iptc_append_entry(d->dest, e, handle)) {
		fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
		return (1);
	}
	free(e);
	return 0;
}

static int
delete_rule (raw_rule_type *d, struct xtables_rule_match *matches, const struct xtables_target *target)
{
	struct ipt_entry *e = NULL;
	unsigned char *mask = NULL;
	int ret=1;

	if (prepare_entry(d, &e)!=0)
		return (1);

	if (verbose>1) {
		printf("Deleting rule\n");
		print_firewall_line(e, handle);
	}

	mask = make_delete_mask(matches, target);
	ret &= iptc_delete_entry(d->dest, e, mask, handle);
	free(e);
	return ret;
}

/** Setup chains if they doesn't exist 
 *
 */
static int 
setup_tables(void)
{
	if (verbose)
		fprintf(stderr, "Setup tables..\n");
	if (!iptc_is_chain("ipac~fi", handle))
		if (!iptc_create_chain("ipac~fi", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
	if (!iptc_is_chain("ipac~fo", handle))
		if (!iptc_create_chain("ipac~fo", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
	if (!iptc_is_chain("ipac~i", handle))
		if (!iptc_create_chain("ipac~i", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
	if (!iptc_is_chain("ipac~o", handle))
		if (!iptc_create_chain("ipac~o", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
	return 0;
};

static int
flush_acc_tables(void)
{
	raw_rule_type *d, *d1;

	if (iptc_is_chain("ipac~fi", handle))
		if (!iptc_flush_entries("ipac~fi", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
	if (iptc_is_chain("ipac~fo", handle))
		if (!iptc_flush_entries("ipac~fo", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
	if (iptc_is_chain("ipac~i", handle))
		if (!iptc_flush_entries("ipac~i", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
	if (iptc_is_chain("ipac~o", handle))
		if (!iptc_flush_entries("ipac~o", handle)) {
			fprintf(stderr, "iptables: %s\n", iptc_strerror(errno));
			return (1);
		}
// Try to flush our old chains
	if (access_agent->get_raw_list("iptables", "", &d)) {
		fprintf(stderr, "access error\n");
		return 1;
	}
	d1=d;
	while(d) {
		if (strlen(d->name)>7)
			if (!memcmp(d->name, "%chain%", 7))
				if (iptc_is_chain(d->name+8, handle)) {
					iptc_flush_entries(d->name+8, handle);
					if (verbose>1)
						fprintf(stderr, "flushing chain '%s'\n", d->name+8);
				}
					
		d=d->next;
	}
	free_raw_list(d1);
	return 0;
}


int iptables_ipac_init(int flag)
{
	int ret;

	iptables_globals.program_name = "iptables";
	ret = xtables_init_all(&iptables_globals, NFPROTO_IPV4);
	if (ret < 0) {
		fprintf(stderr, "%s %s Failed to initialize xtables\n",
				"fetchipac",
				VERSION);
				exit(1);
	}

	if (!handle)
		handle = iptc_init("filter");

	if (!handle) {
//		try to insmod the module if iptc_init failed
		if (!handle && xtables_load_ko(xtables_modprobe_program, false) != -1)
			handle = iptc_init("filter");
	}

	if (!handle) {
		fprintf(stderr, "ipac-ng: can't initialize iptables table `filter'\n"
		"\tis \"Network packet filtering (replaces ipchains)\"\n"
		"\tin Networking options of your kernel enabled?\n"
		"\tif so then you *have* to enable \"IP tables support\" in\n"
		"\t\"IP: Netfilter Configuration\" *and* \"Packet filtering\"\n"
		"\tsome lines below in your kernel configuration.\n"
		"\tPlease don't send bug reports\n"
		"\tif you failed to enable these features! \n"
		"\t You have to check that /usr/include/linux points to the\n"
		"\tright kernel's headers (somewhere in /usr/src/linux/include/linux?).\n"
		"\tIf it's not then you have to correct this and recompile ipac-ng\n"
		"---\nwbw, kaiser.\n\n"
		"\tiptables reported that %s\n", iptc_strerror(errno));
		exit (1);
	}
	return 0;
};

static int 
setup_rules(void)
{
	raw_rule_type *d, *d1;
	char chain[MAX_RULE_NAME_LENGTH+2];
	FILE *frunfile;

	if(access_agent->get_raw_list("iptables", "", &d)) {
		fprintf(stderr, "access error\n");
		return 1;
	}

	frunfile = fopen(RUNFILE, "w");	//needs to make some error handling later
	if (!frunfile) {
		fprintf(stderr, "%s: opening runfile \"%s\": %s\n",
					    me, RUNFILE, strerror(errno));
		return 1;
	}
	d1 = d;
	while(d) {
		/* Trying to implement hierarchic rules */
		strcpy(d->target, ""); /* no target per default */
		strcpy(chain, d->dest); // %-)

		/* Are we dealing with new chain? if so create it */
		if (d->name[0]=='%') {
			if (!strncmp(d->name, "%chain%", 7)) {
				if (strlen(d->name)<8) {
					fprintf(stderr, "error: new "
							"chain name missing\n");
					return 1;
				}
				/* set target to this new chain */
				strcpy(d->target, d->name+8); 
				if (verbose>1)
					fprintf(stderr, "creating chain '%s'\n", d->target);
				iptc_create_chain(d->target, handle);
				fprintf(frunfile, "%s|%%%s%%\n", chain, d->target);
			} else {
				fprintf(stderr, "error: incorrect symbol %% "
						"in rule name\n");
				return 1;
			}
		} else
			if (!(((strlen(chain)>4) && 
				    (!memcmp(chain+strlen(chain)-4, "~c", 2))) ||
			    ((strlen(chain)>5) &&
				    (!memcmp(chain+strlen(chain)-5, "~c", 2)))))
				fprintf(frunfile,"%s|%s\n", chain, d->name);
				
		strcpy(d->dest, chain);
		append_rule(d);
		d=d->next;
	}
	fclose(frunfile);
	free_raw_list(d1);
	return 0;
}

/** 
 Setup all possible rules in iptables 
 */
int iptables_ipac_set(rule_type **firstrule, int first)
{
	unsigned int ref=0;
	raw_rule_type d;
	bzero((void *) &d, sizeof(raw_rule_type));

	if (verbose)
		fprintf(stderr, "Flushing accounting chains..\n");
	flush_acc_tables();
	if (verbose)
		fprintf(stderr, "Setting up acc chains..\n");
	if (first==1)
		setup_tables();
	if (verbose)
		fprintf(stderr, "Setting up accounting rules..\n");
    	setup_rules();
	
	if (first==1) {
		iptc_get_references(&ref, "ipac~fi", handle);
		if (ref!=0) {
			strcpy(d.dest, "OUTPUT"); strcpy(d.snet, "0/0"); strcpy(d.dnet, "0/0");
			strcpy(d.target, "ipac~i");
			delete_rule(&d, NULL, xtables_targets);
			strcpy(d.dest, "FORWARD"); strcpy(d.target, "ipac~fi");
			delete_rule(&d, NULL, xtables_targets);
		}
		iptc_get_references(&ref, "ipac~fo", handle);
		if ((ref!=0) && (first==1)) {
			strcpy(d.dest, "INPUT"); strcpy(d.snet, "0/0"); strcpy(d.dnet, "0/0");
                        strcpy(d.target, "ipac~o");
			delete_rule(&d, NULL, xtables_targets);
			strcpy(d.dest, "FORWARD"); strcpy(d.target, "ipac~fo");
			delete_rule(&d, NULL, xtables_targets);
		}
		strcpy(d.dest, "OUTPUT"); strcpy(d.snet, "0/0"); strcpy(d.dnet, "0/0");
		strcpy(d.target, "ipac~i");
		insert_rule(&d, 0);
		strcpy(d.dest, "INPUT"); strcpy(d.target, "ipac~o");
		insert_rule(&d, 0);
		strcpy(d.dest, "FORWARD"); strcpy(d.target, "ipac~fo");
		insert_rule(&d, 0);
		strcpy(d.dest, "FORWARD"); strcpy(d.target, "ipac~fi");
		insert_rule(&d, 0);
	}
	iptc_commit(handle);
	iptables_ipac_init(0);
	return 0;
}

int 
iptables_ipac_read(rule_type **firstrule)
{
	struct runfile_line_type *runfile;

	runfile = read_runfile();
	if (runfile == NULL)
		return 1;

	return read_iptables(runfile, firstrule);
}

int
iptables_ipac_check(void){
	unsigned int tmp=0;	

	if ((iptc_is_chain("ipac~fi", handle) +
		iptc_is_chain("ipac~fo", handle))!=2)
		return 1;
	iptc_get_references(&tmp, "ipac~fo", handle);
	if (tmp==0)
		return 1;
	iptc_get_references(&tmp, "ipac~fi", handle);
	if (tmp==0)
		return 1;
	return 0;
}

void
flush_remove_chain(char *ch_name)
{
	if (!handle)
		iptables_ipac_init(0);
	if (iptc_is_chain(ch_name, handle)) {
		iptc_flush_entries(ch_name, handle);
		iptc_delete_chain(ch_name, handle);
		iptc_commit(handle);
		iptables_ipac_init(0);	// always do init after commit!
	}
}

/*
 * Deny packets from any to any.
 * Make by inserting drop rule to the forward chain
 */
int 
iptables_ipac_alarm(void)
{
	int ret;
	raw_rule_type d;
	bzero((void *)&d, sizeof(raw_rule_type));
        if (!handle)
                iptables_ipac_init(0);
	strcpy(d.dest, "FORWARD"); strcpy(d.target, "DROP");
	ret = insert_rule(&d, 0);
	iptc_commit(handle);
	return ret;
}
