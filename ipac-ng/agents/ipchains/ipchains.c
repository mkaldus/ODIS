/*
 *
 * $Id: ipchains.c,v 1.4 2003/11/14 19:51:29 friedl Exp $
 *
 * postgresql backend to ipac
 * Copyright (C) 2001 Al Zaharov
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

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/param.h>
#include <unistd.h>
#include <search.h>
#include <assert.h>
#include <netdb.h>
#include <stdarg.h>

#include "../../ipac.h"
#include "libipfwc.h"
#include "../../lib/libnet.h"

/** structure for run file (rule file) */
struct runfile_line_type {
	char *line;
	struct runfile_line_type *next;
};

static void parse_ports(const char *portstring, __u16 *ports, __u16 proto);
static __u16 parse_port(const char *port, unsigned short proto);
static int service_to_port(const char *name, unsigned short proto);
static unsigned short parse_interface(const char *ifstring, char *vianame);
/* ----------------------------------------------------- */

static int flush_acc_chains(void);

/* plain file ipac interface entries */
int ipchains_ipac_init(int flag);
int ipchains_ipac_set(rule_type **firstrule, int first);
int ipchains_ipac_read(rule_type **firstrule);
int ipchains_ipac_check(void);

static const acc_agent_t interface_entry = {
	"ipchains",
	ipchains_ipac_init,
	ipchains_ipac_set,
	ipchains_ipac_read,
	ipchains_ipac_check,
};

const acc_agent_t *ipac_ag_interface_ipchains() {
	return &interface_entry;
}

static void
parse_ports(const char *portstring, __u16 *ports, __u16 proto)
{
	char *buffer;
	char *cp;

	if (portstring == NULL) {
		ports[0] = 0;
		ports[1] = 0xFFFF;
		return;
	}
	if (portstring[0] == '\0') {
		ports[0] = 0;
		ports[1] = 0xFFFF;
		return;
	}

	buffer = strdup(portstring);
	if ((cp = strchr(buffer, ':')) == NULL) {
		ports[0] = ports[1] = parse_port(buffer, proto);
	} else {
		*cp = '\0';
		cp++;

		ports[0] = buffer[0] ? parse_port(buffer, proto) : 0;
		ports[1] = cp[0] ? parse_port(cp, proto) : 0xFFFF;
	}
	free(buffer);
}

static __u16
parse_port(const char *port, unsigned short proto)
{
	int portnum;

	if (proto != IPPROTO_ICMP
	    && proto != IPPROTO_TCP
	    && proto != IPPROTO_UDP) {
		fprintf(stderr, "can only specify ports for icmp, tcp or udp\n");
		exit(1);
	}
	else if ((portnum = string_to_number(port, 0, 65535)) != -1)
		return (unsigned short) portnum;
	else if (proto == IPPROTO_ICMP) {
		/* ICMP types (given as port numbers) must be numeric! */
		fprintf(stderr, "invalid ICMP type `%s' specified\n", port);
		exit(1);
	} else if ((portnum = service_to_port(port, proto)) != -1)
		return (unsigned short) portnum;
	else {
		fprintf(stderr, "invalid port/service `%s' specified", port);
		exit(1);
	}
}

static int
service_to_port(const char *name, unsigned short proto)
{
	struct servent *service;

	if (proto == IPPROTO_TCP
	    && (service = getservbyname(name, "tcp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else if (proto == IPPROTO_UDP
		 && (service = getservbyname(name, "udp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else
		return -1;
}

static unsigned short
parse_interface(const char *ifstring, char *vianame)
{
	int ret;
	if (strlen(ifstring) > IFNAMSIZ) {
		fprintf(stderr, "ipchains: parameter problem: "
			   "interface name `%s' must be shorter than"
			   " IFNAMSIZ (%i)",
			   ifstring, IFNAMSIZ);
		exit (1);
	}

	strncpy(vianame, ifstring, IFNAMSIZ);
	if (vianame[0] == '\0')
		return IP_FW_F_WILDIF;
	else if(vianame[strlen(ifstring)-1] == '+') {
		vianame[strlen(ifstring)-1] = '\0';
		ret = IP_FW_F_WILDIF;
	}
	else ret = 0;

	return ret;
}

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
struct runfile_line_type
*read_runfile()
{
	FILE *frunfile;
	char runfile_line[MAX_RULE_NAME_LENGTH + 50], *cp;
	struct runfile_line_type *result, *lastline, *cur;

	int tmp = 0;

	frunfile = fopen(RUNFILE, "r");
	if (frunfile == NULL) {
		fprintf(stderr, "%s: cant open run file \"%s\": %s "
				"(fetchipac -S not run?)\n",
			me, RUNFILE, strerror(errno));
		return NULL;
	}

	result = NULL;
	lastline = NULL;
	while(fgets(runfile_line, MAX_RULE_NAME_LENGTH+50, frunfile) != NULL)
	{
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
	if (!feof(frunfile))
	{
		fprintf(stderr, "%s: reading \"%s\": %s\n",
			me, RUNFILE, strerror(errno));
		fclose(frunfile);
		destroy_runfile_lines(result);
		result = NULL;
	}
	fclose(frunfile);
	return result;
}

/** read kernel accounting data in ipchains system
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
read_ipchains(FILE *f, struct runfile_line_type *runfile,
			rule_type **firstrule)
{
	char procfile_line[MAX_PROCFILE_LINE_LENGTH], *cp="\0";
	rule_type *rule, *lastrule, search_rule;
	raw_rule_type *raw;
	struct runfile_line_type *nextline, *line_before;
	char chain_name[10];
	unsigned long bytes_hi, bytes_lo, pkts_hi, pkts_lo;
	UINT64 bytes, pkts;
	void *node;
	void *ruletree = NULL;
	rule_type *chain;
	void *chaintree = NULL;

	chain = NULL;
	/* fill tree with our chain names */
	if(access_agent->get_raw_list("ipchains", "", &raw)) {
		fprintf(stderr, "access error getting rules list\n");
		return 1;
	}

	chain = new_rule();
	strcpy(chain->name, CH_INNAME);
	if (!tsearch(chain, &chaintree, rule_compare)) {
		perror("Insuficient memory\n");
		exit (1);
	}
	chain = new_rule();
	strcpy(chain->name, CH_OUTNAME);
	if (!tsearch(chain, &chaintree, rule_compare)) {
		perror("Insuficient memory\n");
		exit (1);
	}

	while(raw)
	{
		if (!memcmp(raw->name, "%chain%", 7)) {
			chain = new_rule();
			strcpy(chain->name, raw->name+8);
			if (!tsearch(chain, &chaintree, rule_compare)) {
				perror("Insuficient memory\n");
				exit (1);
			}
			if (verbose>2)
				printf("new chain \"%s\" added to a tree\n", 
								chain->name);
		}
// FIXME: error handling in case there are two identical chains in config
		raw = raw->next;
	}
	/* create the rule_type records in correct order as from
	 * run file.
	 */
	lastrule = *firstrule = NULL;
	for (nextline=runfile; nextline!=NULL; nextline=nextline->next)
	{
		cp = strchr(nextline->line, '|');
		if (cp == 0)
			continue;	/* bad entry */
		rule = new_rule();
		strncpy(rule->name, cp+1, MAX_RULE_NAME_LENGTH);
		/* use a binary tree to find rules with same name */
		node = tsearch(rule, &ruletree, rule_compare);
		if (*(rule_type **)node != rule)
		{
			free(rule);
		} else {
			if (lastrule != NULL)
				lastrule->next = rule;
			lastrule = rule;
			if (*firstrule == NULL)
				*firstrule = rule;
		}
	}
	chain = new_rule();
	while(fgets(procfile_line, MAX_PROCFILE_LINE_LENGTH, f) != NULL)
	{
		if (sscanf(procfile_line, "%s"
					  "%*X/%*X->%*X/%*X "
			    		"%*s "			/* Interface */
			    		"%*X %*X "		/* flg & invflg */
			    		"%*u "			/* Protocol */
			    		"%lu %lu %lu %lu "	/* Counters */
			    		"%*u-%*u %*u-%*u "	/* Ports */
			    		"A%*X X%*X "		/* TOS masks */
			    		"%*X "			/* fw_redir */
			    		"%*u "			/* fw_mark */
			    		"%*u "			/* output size */
			    		"%s",			/* Target */
				chain_name, &pkts_hi, &pkts_lo, &bytes_hi,
					&bytes_lo, chain->name) != 6)
		{
			fprintf(stderr, "%s: parse error reading proc "
						    "accounting file\n", me);
			return 1;
		}
		if (verbose>2)
			printf("read from proc: chain name - \"%s\", "
				"target - \"%s\"\n", chain_name, chain->name);
		if (!tfind(chain, &chaintree, rule_compare)) {
			strcpy(chain->name, chain_name);
			/* is this ours ? */
			if (tfind(chain, &chaintree, rule_compare) != NULL) {
				if (!runfile) {
					fprintf(stderr, "%s: more kernel accounting "
					    "data than rules in \"%s\" - extra ignored"
					    "\n(run fetchipac -S to fix this)\n",
					    me, RUNFILE);
					break;
				}

				bytes = bytes_lo + ((UINT64)bytes_hi << 32);
				pkts = pkts_lo + ((UINT64)pkts_hi << 32);

				/* find appropriate runfile line */
				line_before = NULL;
				for (nextline = runfile; nextline != NULL;
					line_before=nextline,
					nextline=nextline->next)
				{
					cp = strchr(nextline->line, '|');
					if (cp == 0)
						continue;	/* bad entry */
					if (strncmp(nextline->line, chain_name,
							cp-nextline->line) == 0)
						break;
				}
				if (nextline == NULL) {
					fprintf(stderr, "%s: out of rule names for "
						"chain %s in \"%s\"\n"
						" (something corrupted ipac settings, r"
						"un fetchipac -S to restore)\n",
						me, chain_name, RUNFILE);
					return 1;
				}

				/* use the binary tree to find the rule */
				strncpy(search_rule.name, cp+1, MAX_RULE_NAME_LENGTH);
				node = tfind(&search_rule, (void * const *)&ruletree,
					rule_compare);
				assert(node != NULL);
				rule=*(rule_type **)node;
				rule->pkts += pkts;
				rule->bytes += bytes;
				if (line_before != NULL)
					line_before->next = nextline->next;
				else
					runfile = nextline->next;
				free(nextline->line);
				free(nextline);
			}
		}
	}
	free(chain);
	if (runfile) {
		fprintf(stderr, "%s: more rules in \"%s\" than in kernel\n"
			"(run fetchipac -S to fix this)\n",
			me, RUNFILE);
	}
	free_tree(&ruletree);
	free_tree(&chaintree);
	return 0;
}

/*
 * Setup chains if they doesn't exist
 */
static int 
setup_chains()
{
	static struct ip_fwuser fw;
	unsigned int nsaddrs = 0;
	struct in_addr *saddrs = NULL;

	parse_hostnetworkmask("0/0", &saddrs, &(fw.ipfw.fw_smsk), &nsaddrs);
	parse_ports(NULL, fw.ipfw.fw_spts, fw.ipfw.fw_proto);
	parse_hostnetworkmask("0/0", &saddrs, &(fw.ipfw.fw_dmsk), &nsaddrs);
	parse_ports(NULL, fw.ipfw.fw_dpts, fw.ipfw.fw_proto);
	ipfwc_create_chain(CH_INNAME);
	ipfwc_create_chain(CH_OUTNAME);
	strcpy(fw.label, CH_INNAME);
	ipfwc_delete_entry("input", &fw);
	ipfwc_append_entry("input", &fw);
	strcpy(fw.label, CH_OUTNAME);
	ipfwc_delete_entry("output", &fw);
	ipfwc_append_entry("output", &fw);
	return 0;
};

static int
flush_acc_chains(void)
{
	raw_rule_type *d;

	ipfwc_flush_entries(CH_INNAME);
	ipfwc_flush_entries(CH_OUTNAME);
	ipfwc_flush_entries(CH_CTRL_IN);
	ipfwc_flush_entries(CH_CTRL_OUT);
	if(access_agent->get_raw_list("iptables", "", &d)) {
		fprintf(stderr, "access error\n");
		return 1;
	}

	while(d)
	{
		if (!memcmp(d->name, "%chain%", 7))
			ipfwc_flush_entries(d->name+8);
		d=d->next;
	}
	return 0;
}

int ipchains_ipac_init(int flag)
{
	return 0;
};

static int
check_inverse(char *src)
{
	char tmp[MAX_RULE_NAME_LENGTH];
	if (src) {
                if (memcmp(src, "!", 1) == 0) {                              
                        int slen = strlen(src);

                        //strip the "!"
			strcpy(tmp, src+1);
			strcpy(src, tmp);
//                        memcpy(src, src+1, slen);

                        //if all there was, was a `!' after doing the strip,
                        // return no inverse and don't complain about it.
                        if (slen == 1)
                        	return 0;

                        if (memcmp(src, "!", 1) == 0) {
				fprintf(stderr, 
					"Multiple `!' flags not allowed");
				exit(1);
			}
                        return 1;
                }
	}
	return 0;
}

static int
setup_rules(void) {
	raw_rule_type *d;
	static struct ip_fwuser fw;
	unsigned int nsaddrs = 0, ndaddrs = 0;
	struct in_addr *saddrs = NULL, *daddrs = NULL;
	FILE *frunfile;
	char chain[10];	// ipchains limits chain name to 8 chars + '\0'

	if(access_agent->get_raw_list("ipchains", "", &d)) {
		fprintf(stderr, "access error getting rules list\n");
		return 1;
	}
	frunfile = fopen(RUNFILE, "w");
	if (!frunfile) {
		fprintf(stderr, "%s: opening runfile \"%s\": %s\n",
			me, RUNFILE, strerror(errno));
		return 1;
	}
	while(d)
	{
		if (verbose>1)
			printf("\"%s\" | \"%s\" | \"%s\" | \"%s\" | \"%s\" \"%s\" | \"%s\" \"%s\"\n",
			    d->name, d->dest, d->iface, d->protocol,
			    d->snet, d->sport, d->dnet, d->dport);
		memset(&fw, 0, sizeof(fw));
		fw.ipfw.fw_tosand = 0xFF;	//default TOS 'and' and 'xor' masks
		fw.ipfw.fw_tosxor = 0x00;
		if (check_inverse(d->snet))
			fw.ipfw.fw_invflg |= IP_FW_INV_SRCIP;
		if (check_inverse(d->dnet))
			fw.ipfw.fw_invflg |= IP_FW_INV_DSTIP;
		if (check_inverse(d->iface))
			fw.ipfw.fw_invflg |= IP_FW_INV_VIA;
		if (check_inverse(d->protocol))
			fw.ipfw.fw_invflg |= IP_FW_INV_PROTO;
		if (check_inverse(d->sport))
			fw.ipfw.fw_invflg |= IP_FW_INV_SRCPT;
		if (check_inverse(d->dport))
			fw.ipfw.fw_invflg |= IP_FW_INV_DSTPT;
		
		parse_hostnetworkmask(d->snet, &saddrs, &(fw.ipfw.fw_smsk),
								    &nsaddrs);
		parse_hostnetworkmask(d->dnet, &daddrs, &(fw.ipfw.fw_dmsk),
								    &ndaddrs);
		if (d->protocol[0]=='\0')
			strcpy(d->protocol, "all");

		fw.ipfw.fw_flg |= parse_interface(d->iface, fw.ipfw.fw_vianame);

		fw.ipfw.fw_proto = parse_protocol(d->protocol);
		if (fw.ipfw.fw_proto != IPPROTO_ICMP) {
			parse_ports(d->sport, fw.ipfw.fw_spts,
							    fw.ipfw.fw_proto);
			parse_ports(d->dport, fw.ipfw.fw_dpts,
							    fw.ipfw.fw_proto);
		} else {
			parse_ports(NULL, fw.ipfw.fw_spts, fw.ipfw.fw_proto);
                        parse_ports(NULL, fw.ipfw.fw_spts, fw.ipfw.fw_proto);
		}

		strcpy(fw.label, "");		// jump to
		fw.ipfw.fw_src.s_addr = saddrs[0].s_addr;
		fw.ipfw.fw_dst.s_addr = daddrs[0].s_addr;

		if (!memcmp(d->dest, "out", 3))	{
			strncpy(chain, CH_OUTNAME, 9);
		} else if (!memcmp(d->dest, "in", 2)) {
			strncpy(chain, CH_INNAME, 9);
		} else {
			strncpy(chain, d->dest, 9);
		}

		if (!strncmp(d->name, "%chain%", 7)) {	// new chain?
			if (strlen(d->name)<10) {
				fprintf(stderr, "error: new chain "
							    "name missing\n");
				return 1;
			}
			if (verbose>1)
				printf("Creating chain \"%s\"\n", d->name+8);
			ipfwc_create_chain(d->name+8);
			strcpy(fw.label, d->name+8);
			fprintf(frunfile, "%s|%%\n", chain);
		} else
			fprintf(frunfile,"%s|%s\n", chain, d->name);
		if (verbose>2)
			printf("Appending rule to chain \"%s\"\n", chain);
		if (!ipfwc_append_entry(chain, &fw))
			printf("ipchains: %s\n", ipfwc_strerror(errno));
		d=d->next;
	}
	fclose(frunfile);
	return 0;
}

/** 
 Setup all possible rules in ipchains 
 */
int ipchains_ipac_set(rule_type **firstrule, int first)
{
	if (verbose)
		fprintf(stderr, "Flushing acc chains..\n");
	flush_acc_chains();
	if (verbose)
		fprintf(stderr, "Setting up acc chains..\n");
	setup_chains();
	if (verbose)
		fprintf(stderr, "Setting accounting rules..\n");
	return setup_rules();
}


int ipchains_ipac_read(rule_type **firstrule)
{
	FILE *fprocfile;
	char *procfile;
	struct runfile_line_type *runfile;
	int retval;

	runfile = read_runfile();
	if (runfile == NULL)
		return 1;

	procfile = IPCHAINS_PROC_C;

	/* open in read/write mode to reset counters */
	fprocfile = fopen(procfile, "r+");
	if (fprocfile == NULL)
	{
		fprintf(stderr, "%s: cant open \"%s\": %s\n",
				me, procfile, strerror(errno));
		return 1;
	}

	retval = read_ipchains(fprocfile, runfile, firstrule);

	fclose(fprocfile);
	
	return retval;
}

int
ipchains_ipac_check(void)
{
	return 0;
}
