#ifndef SJ_UTILS_H
#define SJ_UTILS_H

/* loglevels */
#define ALL_LEVEL		0
#define ALL_LEVEL_NAME		"default"
#define VERBOSE_LEVEL		1
#define VERBOSE_LEVEL_NAME	"verbose"
#define DEBUG_LEVEL		2
#define DEBUG_LEVEL_NAME	"debug"
#define PACKETS_DEBUG		3
#define PACKETS_DEBUG_NAME	"packets"
#define HACKS_DEBUG		4
#define HACKS_DEBUG_NAME	"hacks"

void check_call_ret(const char *umsg, int objerrno, int ret, bool fatal);
void internal_log(FILE *forceflow, int errorlevel, const char *msg, ...);

#endif /* SJ_UTILS_H */

