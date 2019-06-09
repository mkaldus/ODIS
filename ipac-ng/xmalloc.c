/*
 *
 * $Id: xmalloc.c,v 1.2 2003/07/06 11:34:51 kaiser13 Exp $
 *
 * Copyright (C) 1997 - 2000 Moritz Both
 *               2001 Al Zaharov    
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

#include <stdlib.h>
#include <string.h>
#include "ipac.h"

void *xmalloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL)
	{
		perror(" malloc failed\n");
		exit(1);
	}
	return p;
}

char *xstrdup(const char *s)
{
	char *s1 = xmalloc(strlen(s)+1);
	strcpy(s1, s);
	return s1;
}

void *xrealloc(void *ptr, size_t size)
{
	void *p;
	if ((p = realloc(ptr, size)) == NULL)
	{
		perror(" realloc failed\n");
		exit(1);
	}
	return p;
}

void *
xcalloc(size_t count, size_t size)
{
	void *p;
	
	if ((p = calloc(count, size)) == NULL) {
		perror(" calloc failed\n");
		exit(1);
	}
	return p;
}
