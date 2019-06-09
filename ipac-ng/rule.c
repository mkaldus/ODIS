/*
 *
 * $Id: rule.c,v 1.6 2009/08/02 13:49:41 mdw21 Exp $
 *
 * Copyright (C) 1997 - 2000 Moritz Both
 * 			2001 Al Zaharov
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
#include <string.h>
#include <stdlib.h>

rule_type *new_rule()
{
	rule_type *rule = (rule_type *)xcalloc(sizeof(rule_type), 1);
	rule->next = NULL;
	rule->pkts = 1;
	return rule;
}

user_list 
*new_user()
{
	user_list *user = (user_list *)xcalloc(sizeof(user_list), 1);
	user->next = NULL;
	return user;
}

raw_rule_type 
*new_raw_rule()
{
	raw_rule_type *rule = (raw_rule_type *)xcalloc(sizeof(raw_rule_type), 1);
	// PFM!! :-O
	bzero(rule, sizeof(raw_rule_type));
	return rule;
}

int rule_compare(const void *p1, const void *p2)
{
	return strcmp(((rule_type *)p1)->name, ((rule_type *)p2)->name);
}

/* free all memory used by array of type data_record_type
 * the array has n elements.
 */
void free_data_record_type_array(data_record_type *data, int n)
{
	/* FIXME: the following variables are only needed in the loop
	int i;
	data_record_type *dr;
	rule_type *r;
	*/

	/* FIXME: there's no usefull code here so don't do the loop
	for (i=0, dr=data; i<n; i++, dr++)
	{
	*/
		/* FIXME: we currently don't store the machine name
		if (dr->machine_name != NULL)
			free(dr->machine_name);
		*/
		/* FIXME: should delegate this to the storage module
		          as it knows better how to free this
		          
		while(dr->firstrule != NULL)
		{
			r = dr->firstrule->next;
			free(dr->firstrule);
			dr->firstrule = r;
		}
		*/
	/*
	}
	*/
	free(data);
}


/* free all memory used by array of type data_record_type
 * the array has n elements.
 */
void 
free_raw_list(raw_rule_type *data)
{
	raw_rule_type *r;
	r=data;
	while(data) {
		r=data->next;
		free(data);
		data=r;
	}
}

/* compare two timestamp_t's (for qsort()) */
int compare_timestamp_t(const void *t1, const void *t2)
{
	return *(timestamp_t *)t1 - *(timestamp_t *)t2;
}
