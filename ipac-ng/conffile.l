%option noyywrap
%option caseless 8bit
%option nounput
%x par

%{
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "ipac.h"
#include "conffile.tab.h"

int confline = 1;

%}

%%
#[^\n]*[\n]?                		if(yytext[yyleng-1] == '\n') confline++;
\=					BEGIN(par); return EQUAL;
<par>[ \t]+				/* Eat */ ;
<par>yes|true				BEGIN(0); conflval.n = 1; return BOOL;
<par>no|false				BEGIN(0); conflval.n = 0; return BOOL;
<par>[[:alnum:]\/\-\.]+|[ \t]*\n	BEGIN(0); conflval.s = (char *) strdup(conftext); confline++; return PARAMETER;
"access"[ \t]+"agent"		 	return ACCESS;
"account"[ \t]+"agent"			return ACCOUNT;
"hostname"				return HOSTNAME;
"storage"				return STORAGE;
"rules"[ \t]+"file"			return RULES;
"login"[ \t]+"at"[ \t]+"start"		return SLOGIN;
"auth"[ \t]+"host"[ \t]+		return AUTHHOST;
"drop"[ \t]+"zero"[ \t]+"lines"[ \t]+	return DROPZERO;
"db"[ \t]+"host"[ \t]+			return DBHOST;
"db"[ \t]+"port"[ \t]+			return DBPORT;
"db"[ \t]+"name"[ \t]+			return DBNAME;
"db"[ \t]+"user"[ \t]+			return DBUSER;
"db"[ \t]+"pass"[ \t]+			return DBPASS;
[\n]+					confline++ ;
<*>[[:space:]]				if(*yytext == '\n') confline++;
<*>.					;
<*><<EOF>>      			yyterminate();
%%
