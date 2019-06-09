#ifndef SHAREDSQL_H
#define SHAREDSQL_H

#ifdef DEBUG_DB
#define DEBUG_DB_LOGFILE "dblog"
static int fd;
static void debuglog(const char *format, ...);
#define DPRINTF(fmt, args...) debuglog(fmt, ##args)
#else
#define DPRINTF(fmt, args...)
#endif

static void sql_stor_open ();
static int sql_stor_store_record (const data_record_type *data);
static int sql_stor_list_timestamps (timestamp_t start, timestamp_t end,
		timestamp_t **data, timestamp_t *just_before,
		timestamp_t *just_after, char *ahost);
static int sql_stor_get_records (timestamp_t timestamp_b, timestamp_t timestamp_e, 
		data_record_type **data, char *filter);
static int sql_stor_get_summary (timestamp_t timestamp_b, timestamp_t timestamp_e,
		data_record_type **data, char *filter);
static int sql_stor_delete_record (timestamp_t timestamp);
static void sql_stor_clear ();
static void sql_stor_close ();


#endif /* SHAREDSQL_H */
