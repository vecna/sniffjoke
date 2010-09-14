/* 
 * This file include the headers commonly used in every .cc file
 */

#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <unistd.h>

#include "defines.h"

/* not used ATM */
#define SUPPRESS_LOG		1

/* loglevels */
#define ALL_LEVEL               2
#define ALL_LEVEL_NAME          "default"
#define VERBOSE_LEVEL           3
#define VERBOSE_LEVEL_NAME      "verbose"
#define DEBUG_LEVEL             4
#define DEBUG_LEVEL_NAME        "debug"
#define PACKETS_DEBUG           5
#define PACKETS_DEBUG_NAME      "packets"
#define HACKS_DEBUG             6
#define HACKS_DEBUG_NAME        "hacks"

void check_call_ret(const char *umsg, int objerrno, int ret, bool fatal);
void internal_log(FILE *forceflow, int errorlevel, const char *msg, ...);
