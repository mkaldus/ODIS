%{

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "ipac.h"

#define OUTPUT stdout
#define MAX_LINE_LENGTH		256

/*
 * #define YYDEBUG 0
 */

/* a flag indicating that a rule name is expected
 * to the end of line (special condition for lexical
 * analyser function yylex())
 */
int rule_name_expected = 0;

extern int print_records(FILE *f, int n, const data_record_type *dr);

static FILE *input;

/* a counter for the number of successful performed add commands. */
static int n_add_commands = 0;

/* a flag indicating if we are reading from the spool file. */
static int reading_from_spool_file = 0;

static void print_prompt();

int yyerror(char *s);
int yyparse (void);
int yylex(void);

extern FILE *yyin;

%}

%union {
	char 			*s;
	unsigned long long	n;
	rule_type		*rule;
	data_record_type	*record;
}

%token <n> NUMBER
%token <s> RULENAME WORD
%token LF
%token QUIT DELETE ADD BILL LIST DELIMITER
%token AHOST


%type <rule> rule rules
%type <record> record records record_array
%type <n> command_item existing_command_item quit_command add_command
%type <n> delete_command list_command

%%

input:	/* empty */
	| input command_item	{
					if ($2 != 0) {
						if (reading_from_spool_file)
							YYABORT;
						else
							fprintf(OUTPUT, "FAILED\n");
					}
					rule_name_expected=0;
					print_prompt();
				};

command_item:
	error LF	{ fprintf(OUTPUT, "ERROR: bad command\n"); yyerrok; 
					$$=0;}
	| existing_command_item;


existing_command_item:
	quit_command 
	| delete_command 
	| add_command 
	| list_command;

quit_command:
	QUIT LF		{ YYACCEPT; }
	| QUIT error LF { YYACCEPT; };

delete_command:
	DELETE NUMBER LF	
		{ 
			$$=0;
			if (!storage_opened && storage_method->open(0) !=0)
			{
				fprintf(OUTPUT, "ERROR: cant "
				"open database\n");
				$$=1;
			}
			else
			{
				if (storage_method->delete_record($2) != 0)
				{
					fprintf(OUTPUT, "ERROR: deleti"
						"ng record\n");
					$$=1;
				}
			}
			/* storage_method->close(); */
		}
	| DELETE error LF {
			fprintf(OUTPUT, "ERROR: bad DELETE command format:"
					" expected NUMBER\n");
			$$=1;
		};

add_command:
	ADD LF record_array
		{ 
			int n;
			data_record_type *p;

			$$=0;
			if (!storage_opened && storage_method->open(0) !=0) {
				fprintf(OUTPUT, "ERROR: cant open database\n");
				$$=1;
			} else if ($3 == NULL) {
				$$=1;
			} else {
				storage_opened = 1;
				for (n=0,p=$3; p->machine_name!=NULL;
						n++, p++)
				{
//					timestamp_t before, after, *tlist;	

//					while (storage_method->list_timestamps(p->timestamp, 
//							p->timestamp, &tlist, &before, &after) > 0) 
//						p->timestamp++;
					if (storage_method->store_record(p) 
						!= 0) {
						fprintf(OUTPUT, "ERROR: storing record\n");
						$$=1;
						break;
					} else
						n_add_commands++;
				}
				/* storage_method->close(); */
				free_data_record_type_array($3, n); 
			}
		}
	| ADD error LF {
			fprintf(OUTPUT, "ERROR: bad ADD command format:"
					" expected newline after ADD\n");
			$$=1;
		};

list_command:
	LIST NUMBER NUMBER LF	{
					$$ = list_timestamps($2, $3, NULL);
				}
	| LIST NUMBER NUMBER AHOST WORD LF {
					$$ = list_timestamps($2, $3, $5);
				}

	| LIST error LF {
			fprintf(stderr, "ERROR: bad LIST command format:"
					" expected NUMBER NUMBER\n");
			$$=1;
		};

record_array:	
	NUMBER NUMBER LF records LF {
			data_record_type *p;
			int n;
			if ($4 != NULL)
			{
				for (n=0,p=$4; p->machine_name != NULL; p++,n++)
					p->timestamp = $1;
				if (n != $2)
					;	/* error */
			}
			$$ = $4;
		}
	| error LF {
			fprintf(OUTPUT, "ERROR: parsing record: expected "
					"'timestamp number_of_subrecords "
					"newline ( records ) newline' "
					"sequence\n");
			$$=NULL;
		}
	| NUMBER NUMBER LF error LF {
			fprintf(OUTPUT, "ERROR: parsing record: expected "
					"'( records ) newline' sequence\n");
			$$=NULL;
		};

records:
	records record		{
			int n;
			data_record_type *p;

			if ($1 == NULL)	{
				$$=$2;
			} else {
				if ($2 == NULL)
					$$ = $1;
				else {
					for (p=$1,n=0; p->machine_name != NULL; 
							p++, n++);
					p = (data_record_type *)xmalloc(
						sizeof(data_record_type)*(n+2));
					memcpy(p,$1,sizeof(data_record_type)*n);
					memcpy(p+n,$2,sizeof(data_record_type));
					p[n+1].machine_name = NULL;
					$$ = p;
					free($1);
					free($2);
				}
			}
		}
	| record;

record:	'(' WORD LF rules ')' LF {
			if ($4 != NULL)	{
				$$ = (data_record_type *)xmalloc(sizeof(
						data_record_type)*2);
				$$->machine_name = xstrdup($2);
				$$->firstrule = $4;
				$$[1].machine_name = NULL;
			}
			else
				$$ = NULL;
		};

rules:	rules rule		{
			if ($2 != NULL)
			{
				if ($1 == NULL)
					$1 = $2;
				else
				{
					rule_type *r;
					for (r=$1; r->next != NULL; r=r->next);
					r->next = $2;
				}
			}
			$$ = $1;
		}
	| rule ;

rule:	NUMBER NUMBER DELIMITER RULENAME DELIMITER LF { 
			rule_type *t = new_rule();
			strncpy(t->name, $4, MAX_RULE_NAME_LENGTH);
			t->name[MAX_RULE_NAME_LENGTH] = '\0';
			t->pkts = $2;
			t->bytes = $1;
			$$ = t;
			free($4);
		}
	| error {
			fprintf(OUTPUT, "ERROR: parsing rule line, expected "
					"NUMBER NUMBER | RULENAME | LF\n");
			$$=NULL;
		};
	
%%

int do_batchmode(FILE *in, int *num)
{
	int ret;
	
	reading_from_spool_file = 0;
	input = (in == NULL) ? stdin : in;
	yyin = input;
	print_prompt();
	n_add_commands = 0;
	if (num != NULL)
		reading_from_spool_file = 1;
	ret = yyparse();
/*
	if (storage_opened) {
		storage_method->close();
		storage_opened = 0;
	}
*/
	if (num != NULL)
		*num = n_add_commands;
	return ret;
}

int yyerror(char *s)
{
	/* fprintf(OUTPUT, "ERROR\n"); */
	return 0;
}

void print_prompt()
{
	if (input == stdin) {
		fprintf(OUTPUT, "> ");
		fflush(OUTPUT);
	}
}
