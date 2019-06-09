%option noyywrap
%option nounput
%option caseless 8bit
%x rul clos

%{
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "ipac.h"
#include "batch.tab.h"

%}

%%
[0-9]+		yylval.n = strtoull(yytext, NULL, 10); return NUMBER;
^list		return LIST;
ahost		return AHOST;
^bill		return BILL;
^delete		return DELETE;
^add		return ADD;
^quit		return QUIT;
\|		BEGIN(rul); return DELIMITER;
<clos>\|	BEGIN(0); return DELIMITER;
<rul>[[:alnum:] \t\-\_\(\):\./]+  {
				BEGIN(clos);
				yylval.s = xstrdup(yytext); 
				return RULENAME;
			    }
[a-z0-9\.\-\:]+	yylval.s = (char *) strdup(yytext); return WORD;
\(		return '(';
\)		return ')';
[ \t]+		;
\n		return LF;
%%
