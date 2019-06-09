/*
 *
 * $Id: mysql_backend.h,v 1.2 2004/08/24 18:38:57 friedl Exp $
 *
 * mysql backend to ipac-ng
 * Copyright (C) 2001-2003 Al Zakharov, 2003-2004 Friedrich Lobenstock, 
 *               2004 Simon Hausman, 2004 Denis O.Philippov
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
 * The author can be reached via email: kaiser13@mail2000.ru, or by 
 * fido: Al_Zaharov@p88.f58.n5005.z2.fidonet.org
 *
*/

#ifndef MYSQL_BACKEND_H
#define MYSQL_BACKEND_H

static int mysql_stor_open (int flag);
static int sql_execute_query (const char *query);
static int sql_execute_simple_query (const char *query);
static void sql_clear_result();
static int sql_number_of_affected_rows ();
static const char *sql_result_get_value (int row, int column);
static void sql_close_connection();

#endif /* MYSQL_BACKEND_H */
