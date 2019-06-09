%{

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "ipac.h"
#include "config.h"

#define RULESDEBUG 0

int ruleserror(char *s);
int rulesparse (void);
int ruleslex(void);

raw_rule_type *r, *r1=NULL, *r2, *r3, *r4, *r5, *data;

int sports_u=0;
int dports_u=0;
int slist_u=0;
static int ext_num=2;

extern FILE *rulesin;

%}

%union {
	char		*s;
	unsigned int	n;
}

%token  <s> PARAMETER
%token  <n> BOOL

%token SEP WORD LIST RNAME CHAIN NEWCH EXT_E CIDR

%type <s> commands command

%type <s> RNAME CHAIN WORD CIDR 

%%

input:
	    |
	    input commands;

commands:
	    error	{ /*fprintf(stderr,  "error while parsing config file "
						"near line\n"); yyerrok; 
			*/
				    $$=NULL;
				    }
	    | command;

command:
	    rname chain intf proto source destin extens {
		sports_u = slist_u = dports_u = 0;
		ext_num = 2;
	    }
	    | error {
		fprintf(stderr, "error while parsing config file\n");
		exit(1);
	    };

rname:
		RNAME SEP {
			r = new_raw_rule();
			if (r3 == NULL) {
				r3 = r;
				data = r;
			} else {
			//	r3 = r3->next;
				r2->next = r;
			}
			r1 = r2 = r4 = r5 = r;
			strncpy(r->name, $1, MAX_RULE_NAME_LENGTH);
			if (verbose>1)
				fprintf(stderr, "rule '%s'\n", r->name);
		}
		| SEP { 
			fprintf(stderr, "got empty RULE NAME, abort\n");
			exit (1);
		};
chain:
		CHAIN SEP { 
			strncpy(r->dest, $1, MAX_RULE_NAME_LENGTH);
		}
		| SEP { 
			fprintf(stderr, "chain not specified, abort\n");
			exit(1);
		};
intf:
		WORD SEP { 
			strncpy(r->iface, $1, 8);
		}
		| SEP {
			strcpy(r->iface, "");
		};
proto:
		WORD SEP {
			strncpy(r->protocol, $1, 5);
		}
		| SEP {
			strcpy(r->protocol, "all");
		};
source:
		WORD SEP {
			raw_rule_type *rr = r4;
			while (rr != NULL) {
				strncpy(r->snet, $1, 20);
				rr = rr->next;
			}
		}
		| WORD sports SEP {
			while (r1 != NULL) {
				strncpy(r1->snet, $1, 20);
				if (!(r1->next))
					r2 = r1;
				r1 = r1->next;
			}
		}
		| LIST sips WORD SEP {
			strcpy(r1->name, "%chain% ");
			strcat(r1->name, $3);
			slist_u=1;
			r1=r1->next;
			while (r1 != NULL) {
				strcpy(r1->dest, $3);
				if (!(r1->next))
					r2 = r1;
				r1=r1->next;
			};
		}
		| SEP {
			raw_rule_type *rr = r4;
			while (rr != NULL) {
				strcpy(rr->snet, "0/0");
				rr = rr ->next;
			}
		};
sips:
		sip
		| sips sip;
sip:		
		CIDR {
			r2=new_raw_rule();
			memcpy(r2, r, sizeof(raw_rule_type));
			strncpy(r2->snet, $1, 20);
			r->next=r2;
		};
sports:
		sport
		| sports sport;
sport:
		WORD {
			if (sports_u==1) {
				r2=new_raw_rule();
				memcpy(r2, r, sizeof(raw_rule_type));
				strcpy(r2->snet, r3->snet);
				strncpy(r2->sport, $1, 7);
				r->next=r2;
			} else {
				sports_u = 1;
				r4 = r;
				strcpy(r->snet, r3->snet);
				strncpy(r->sport, $1, 7);
			}
		};
destin:
		WORD SEP {
			while (r4 != NULL) {
				strncpy(r4->dnet, $1, 20);
				r4 = r4->next;
			}
		}
		| WORD dports SEP {
			while (r1 != NULL) {
				strncpy(r1->dnet, $1, 20);
				if (!(r1->next))
					r2 = r1;
				r1 = r1->next;
			}
		}
		| LIST dips WORD SEP {
			strcpy(r1->name, "%chain% ");
			strcat(r1->name, $3);
			r1=r1->next;
			while(r1 != NULL) {
				strcpy(r1->dest, $3);
				if (!r1->next)
					r2 = r1;
				r1=r1->next;
			}
		}
		| SEP {
			while (r4 != NULL) {
				strcpy(r4->dnet, "0/0");
				r4 = r4->next;
			}
		};
dips:
		dip
		| dips dip;
dip:
		CIDR {
			if ((slist_u+sports_u+dports_u)!=0) {
				fprintf(stderr, "can't use ip/ports list in "
					"both source and destination\n");
				exit(1);
			}
			r2=new_raw_rule();
			memcpy(r2, r, sizeof(raw_rule_type));
			strncpy(r2->dnet, $1, 20);
			r->next=r2;
		};
dports:
		dport
		| dports dport;

dport:		WORD {
			if ((slist_u+sports_u)!=0) {
				fprintf(stderr, "can't use ports/ip list in "
					"both source and destination\n");
				exit(1);
			}
			if (dports_u == 1) {
				r2 = new_raw_rule();
				memcpy(r2, r, sizeof(raw_rule_type));
				strcpy(r2->dnet, r3->dnet);
				strncpy(r2->dport, $1, 7);
				r->next = r2;
			} else {
				dports_u = 1;
				r4 = r;
				strcpy(r->dnet, r3->dnet);
				strncpy(r->dport, $1, 7);
			}
		};

extens:		exten
		| extens SEP exten;
exten:
		EXT_E { 
		}
		| WORD {
			unsigned int i=0;
			raw_rule_type *rr = r5;
			rr->extension[ext_num] = xstrdup($1);
			while (rr) {
				memcpy(rr->extension, r5->extension, sizeof(rr->extension));
				for (i=0;i<sizeof(rr->extension)/sizeof(rr->extension[0]);i++)
					if (r5->extension[i])
						rr->extension[i]=xstrdup(r5->extension[i]);
				rr=rr->next;
			}
			ext_num++;
		}
		| {};

%%

static void
print_ext(const raw_rule_type *r)
{
	user_list *ul =  r->extension;
	while(ul) {
		printf(" | %s/%s", ul->login, ul->ip);
		ul = ul->next;
	}
}

int 
parse_rules(FILE *in, raw_rule_type **rules) 
{
	rulesin = (in == NULL) ? stdin : in;
	rulesparse();
	*rules = data;
	return 0;
}

int
ruleserror(char *s)
{
	fprintf(stderr, "Error parsing rules file near line %s\n", s);
	return 0;
}
