/*
 *
 * old "plain file" backend to fetchipac
 * Copyright (C) 2001 Al Zakharov
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

char *rulesfile = NULL;
static int parsed = 0;
static raw_rule_type *parsed_data = NULL;

int parse_rules(FILE *in, raw_rule_type **rules);

/* plain file ipac interface entries */
int files_ipac_open(int flag);
int files_ipac_get_user_list(user_list **list);
int files_ipac_get_raw_list(char *ag_name, char *login, 
		raw_rule_type **data);
int files_ipac_delete_record(timestamp_t timestamp);
double files_ipac_get_cash(char *login);
int files_ipac_set_cash(char *login, double cash);
double files_ipac_get_price(char *rule_name);
double files_ipac_get_kredit(char *login);
int files_ipac_get_pay_type(char *rule_name);
char * files_ipac_get_last_paid(char *service_name);
int files_ipac_set_last_paid(char *login, char *paid);
int files_ipac_login(char *login);
int files_ipac_logout(char *login, double cash);
int files_ipac_close();

static const access_agent_t interface_entry = {
	"files",
	files_ipac_open,
	files_ipac_get_user_list,
	files_ipac_get_raw_list,
	files_ipac_get_cash,
	files_ipac_set_cash,
	files_ipac_get_price,
	files_ipac_get_kredit,
	files_ipac_get_pay_type,
	files_ipac_get_last_paid,
	files_ipac_set_last_paid,
	files_ipac_login,
	files_ipac_logout,
	files_ipac_close
};

const access_agent_t *ipac_ac_interface_files() {
	return &interface_entry;
};


int files_ipac_open(int flag)
{
	/* nothing to do. */
	return 0;
}

// always fails
int files_ipac_login(char *login)
{
	return 1;
}

// always fails too
int files_ipac_logout(char *login, double cash)
{
	return 1;
}

double
files_ipac_get_kredit(char *login)
{
	return 0;
}

int files_ipac_set_last_paid(char *login, char *paid)
{
	return 1;
}

int
files_ipac_get_user_list(user_list **list)
{
	*list = new_user();
	strcpy((*list)->login, "admin");
	return 0;
}

/*
 * new functions are still not fully supported in plain-file method
 * this function is here for compatibility only - it does not support
 * storage agents and login names. Eats old styled config file
 */
int files_ipac_get_raw_list(char *ag_name, char *login, raw_rule_type **data)
{
	FILE *conf;
	raw_rule_type *p,*p1,*p2=NULL,*pb=NULL;
	
	if (verbose)
		fprintf(stderr, "Reading and parsing rules file \"%s\"\n", 
								    rulesfile);

	if (!parsed) {
		if (!rulesfile) {
			fprintf(stderr, "%s: rulesfile is not specified in your "
					"config file\n", me);
			exit (1);
		}
		conf = fopen(rulesfile, "r");
		if (!conf) {
			fprintf(stderr, "%s: opening rules file \"%s\": %s\n",
				me, rulesfile, strerror(errno));
			exit (1);
		}
		parse_rules(conf, data);
		fclose(conf);
		parsed = 1;
		for(p=*data;p;p=p->next) {
			p1 = new_raw_rule();
			if (p2)
				p2->next = p1;
			else
				pb=p1;
			p2 = p1;
			memcpy(p1, p, sizeof(raw_rule_type));
		}
		parsed_data = pb;
	} else {
		*data = parsed_data;
	}
	
	return 0;
}

// This always return positive balance so that old-styled ipac supported
double
files_ipac_get_cash(char *login)
{
	return 1;
}

int files_ipac_set_cash(char *login, double cash)
{
	return 0;
};

double files_ipac_get_price(char *rule_name)
{
	return 0;
};

int files_ipac_get_pay_type(char *rule_name)
{
	return 0;
};

char * files_ipac_get_last_paid(char *service_name)
{
	return NULL;
};

int files_ipac_close(void)
{
	/* nothing to do. */
	return 0;
}
