%option stack
%option noyywrap
%option caseless 8bit
%x chain intf sou des ext proto iplist 

%{
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "ipac.h"
#include "rules.tab.h"

#define MAX_INCL 2
YY_BUFFER_STATE old_st;

%}
ACHAR		[[:alnum:]\%][[:alnum:]\-\_\(\):\./\%\~ \t]*

%%
<*>#[^\n]*[\n]?				/* eat comments */
<INITIAL,chain,sou,des,intf>[ \t]+	;
<INITIAL>{ACHAR}+			{
					ruleslval.s = (char *) xstrdup(yytext);
					return RNAME;
					}
<chain>{ACHAR}+				{
					ruleslval.s = (char *) xstrdup(yytext);
					return CHAIN;
					}
<sou,des>\@[[:alnum:]\.\-\_\/]+\@	{
					ruleslval.s =(char *)xstrdup(yytext+1);
					ruleslval.s[strlen(ruleslval.s)-1]='\0';
					old_st = YY_CURRENT_BUFFER;
					rulesin=fopen(ruleslval.s, "r");
					if (!rulesin) {
						printf("can't open file '%s', aborting\n", ruleslval.s);
						exit(1);
					}
					yy_switch_to_buffer(
						yy_create_buffer(rulesin, YY_BUF_SIZE));
					yy_push_state(iplist);
					return LIST;
					}
<iplist>[ \t\n]				;
<iplist>[[:alnum:]\.\-\_\/\~]+		{
					ruleslval.s = (char *)xstrdup(yytext);
					return CIDR;
					}
<iplist><<EOF>>				{
					yy_delete_buffer(YY_CURRENT_BUFFER);
					yy_switch_to_buffer(old_st);
					yy_pop_state();
					}
<ext>[[:alnum:]\.\-\_\/\~:\!\,]+		{
					ruleslval.s = (char *) xstrdup(yytext);
					return WORD;
					}
<proto,intf,sou,des>[[:alnum:]\.\-\_\/\~]+	{
					ruleslval.s = (char *) xstrdup(yytext);
					return WORD;
					}
<ext>\|				return SEP;
<ext>[ \t]			return SEP;
<ext>\n				BEGIN(INITIAL); return SEP;
<ext><<EOF>>			BEGIN(INITIAL); return SEP;
<des>\|				BEGIN(ext); return SEP;
<sou>\|				BEGIN(des); return SEP;
<proto>\|			BEGIN(sou); return SEP;
<intf>\|			BEGIN(proto); return SEP;
<chain>\|			BEGIN(intf); return SEP;
<INITIAL>\|			BEGIN(chain); return SEP;
<INITIAL>[\n]+				;
<<EOF>>		      			yyterminate();
%%
