#ifndef H__LOGGER_H
#define H__LOGGER_H

/*
 * does runtime logging.
 * xiang hong
 * 2002-07-29
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#define RLOG_LV_DEBUG		10
#define RLOG_LV_INFO		20
#define RLOG_LV_FATAL		30

#define LOGMSG_MAX_LEN		1024

#define RUNTIME_LOG(lv, mod, fmt, args...)	\
	runtime_log((lv), (mod), "file %s, line %d, " fmt, \
	__FILE__, __LINE__, ##args)

/*
 * define your own version of RLOG.
 */
#define RLOGF(fmt, args...)	RLOG(RLOG_LV_FATAL, fmt, ##args)
#define RLOGI(fmt, args...)	RLOG(RLOG_LV_INFO, fmt, ##args)
#define RLOGD(fmt, args...)	RLOG(RLOG_LV_DEBUG, fmt, ##args)

#ifdef __cplusplus
extern "C"
{
#endif
/*
 * returns:
 * 0, if succeeded;
 * -1, if file is not absolute path, or failed to create log file;
 */
int runtime_log_init(char * file, int level);
int system_log_init(char * file, int level);

/*
 * name: runtime_log
 * functionality: appends log message to runtime log file.
 * params:
 * 	level: log level, messages with level value smaller the global var
 * 		"runtime_log_level" are ignored;
 * 	module: name of loggin module;
 * 	fmt: format string;
 * returns:
 * 	none;
 */
void runtime_log(int level, char * module, char * fmt, ...);

/*
 * fake function.
 */
void system_log(int level, char * module, char * fmt, ...);

#ifdef __cplusplus
}
#endif
#endif


