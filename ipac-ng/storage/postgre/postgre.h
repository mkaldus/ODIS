#ifndef POSTGRE_H
#define POSTGRE_H

static int postgre_stor_open (int flag);
static int sql_execute_query (const char *query);
static int sql_execute_simple_query (const char *query);
static void sql_clear_result();
static int sql_number_of_affected_rows ();
static const char *sql_result_get_value (int row, int column);
static void sql_close_connection();

#endif /* POSTGRE_H */
