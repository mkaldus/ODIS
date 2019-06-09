%{

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "ipac.h"
#include "config.h"

#define CONFDEBUG 0

int conferror(char *s);
int confparse (void);
int conflex(void);

extern FILE *confin;
extern char *storage_method_name;
extern char *acc_agent_name;
extern char *access_agent_name;
extern char *rulesfile;
extern char *dbhost;
extern char *dbport;
extern char *dbuser;
extern char *dbname;
extern char *dbpass;
extern int slogin;
extern char *authhost;
extern int dropzero;
extern int confline;

%}

%union {
	char		*s;
	unsigned int	n;
}

%token  <s> PARAMETER
%token  <n> BOOL

%token  EQUAL
%token	ACCESS ACCOUNT STORAGE RULES SLOGIN AUTHHOST DROPZERO ERROR
%token  DBHOST DBPORT DBNAME DBUSER DBPASS
%token  HOSTNAME

%type <s> commands dbhost_opt command dbport_opt access_opt
%type <s> account_opt storage_opt rules_opt slogin_opt authhost_opt dropzero_opt
%type <s> dbname_opt dbuser_opt dbpass_opt hostname_opt

%%

input:
	    |
	    input commands;

commands:
	    error		{ fprintf(stderr,  "error while parsing config file "
						"near line %d\n", confline); yyerrok; 
				    $$=NULL;
				    }
	    | command
	    ;

command:
	    hostname_opt
	    |access_opt
	    |account_opt
	    |storage_opt
	    |rules_opt
	    |slogin_opt
	    |authhost_opt
	    |dropzero_opt
	    |dbhost_opt
	    |dbport_opt
	    |dbname_opt
	    |dbuser_opt
	    |dbpass_opt;

hostname_opt:
		HOSTNAME EQUAL PARAMETER
		{
			if (!hostname)
				hostname = xstrdup(conflval.s);
		}
		| HOSTNAME error {
			fprintf(stderr, "error  while parsing config file\n");
			$$ = NULL;
			};
dbhost_opt:
	    DBHOST EQUAL PARAMETER
		{
			dbhost = xstrdup(conflval.s);
		}
	    | DBHOST error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};

dbport_opt:
	    DBPORT EQUAL PARAMETER
		{
			dbport = xstrdup(conflval.s);
		}
	    | DBPORT error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};


dbname_opt:
	    DBNAME EQUAL PARAMETER
		{
			dbname = xstrdup(conflval.s);
		}
	    | DBNAME error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};


dbuser_opt:
	    DBUSER EQUAL PARAMETER
		{
			dbuser = xstrdup(conflval.s);
		}
	    | DBUSER error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};


dbpass_opt:
	    DBPASS EQUAL PARAMETER
		{
			dbpass = xstrdup(conflval.s);
		}
	    | DBPASS error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};

access_opt:
	    ACCESS EQUAL PARAMETER
		{
			access_agent_name = xstrdup(conflval.s);
		}
	    | ACCESS error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};

account_opt:
	    ACCOUNT EQUAL PARAMETER
		{
			acc_agent_name = xstrdup(conflval.s);
		}
	    | ACCOUNT error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};

storage_opt:
	    STORAGE EQUAL PARAMETER
		{
			if (storage_method_name == NULL)
				storage_method_name = xstrdup(conflval.s);
		}
	    | STORAGE error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};

rules_opt:
	    RULES EQUAL PARAMETER
		{
			rulesfile = xstrdup(conflval.s);
		}
	    | RULES error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};

slogin_opt:
	    SLOGIN EQUAL BOOL
		{
			slogin = conflval.n;
		}
	    | SLOGIN error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};

authhost_opt:
	    AUTHHOST EQUAL PARAMETER
		{
			authhost = xstrdup(conflval.s);
		}
	    | AUTHHOST error
		{
			fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};
		
dropzero_opt:
	    DROPZERO EQUAL BOOL
		{
			dropzero = conflval.n;
		}
	    | DROPZERO error
		{
		    	fprintf(stderr, "error while parsing config file\n");
			$$ = NULL;
		};
%%

int 
parse_config(FILE *in) 
{
	confin = (in == NULL) ? stdin : in;
	return confparse();
}

int
conferror(char *s)
{
	fprintf(stderr, "Error in config file near line %d: %s\n", confline, s);
	exit (1);
}
