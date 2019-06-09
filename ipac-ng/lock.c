/*
 *
 * $Id: lock.c,v 1.2 2003/07/06 11:34:51 kaiser13 Exp $
 *
 * Copyright (C) 1997 - 2000 Moritz Both
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

#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "ipac.h"

int lock(const char *file)
{
	FILE *f;
	int ok = 0;
	char *buf = (char *)malloc(strlen(file) + 20);
	char buf1[20];
	int otherpid;
	char *err;
	int _errno=0;

	err = NULL;
    
	sprintf(buf, "%s.%d", file, getpid());
	f = fopen(buf, "w");
	if (f == NULL) {
		err = "opening lock file for writing";
		_errno = errno;
	} else {
		fprintf(f, "%d", getpid());
		fclose(f);

		if (link(buf, file) == 0)
			ok = 1;
		else if (errno == EEXIST)
		{
			f = fopen(file, "r");
			if (f == NULL) {
				if (errno == ENOENT) {
					/* file WAS there, but now it's gone. 
						Try again next time. */
				} else {
					/* other error - that's bad. */
					err = "opening lock file for reading";
					_errno = errno;
				}
			} else if (fgets(buf1, 19, f) != NULL) {
				otherpid = atoi(buf1);
				if (otherpid > 0) {
					if (kill(otherpid, 0) != 0) {
						if (errno == ESRCH) {
							/*dangling lock file. */
							unlink(file);
							if (link(buf, file)==0)
								ok = 1;
						} else {
							_errno = errno;
							err = "testing process"
								" existance";
						}
					} else {
						/* other process lives */
					}
				} else {
					/* garbage in the lock file */
					err = "finding pid of lock file "
						"owner - garbage in there?";
					_errno = 0;
				}
			} else {
				/* file is there, but cant read pid */
				/* report error */
				err = "reading lock file: cant read";
				_errno = errno;
			}
			fclose(f);
		} else {
			err = "link lock file";
			_errno = errno;
		}
	}

	unlink(buf);
	free(buf);
	if (err) {
		errno = _errno;
		perror(err);
		exit(1);
	}
	return ok == 0;
}

int unlock(const char *file)
{
	if (unlink(file))
		perror("warning: removing lock file");
	return 0;
}
