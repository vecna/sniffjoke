/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010 vecna <vecna@delirandom.net>
 *                      evilaliv3 <giovanni.pellerano@evilaliv3.org>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* 
 * This file include the headers commonly used in every .cc file
 */

#ifndef SJ_UTILS_H
#define SJ_UTILS_H

#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <unistd.h>

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

#endif /* SJ_UTILS_H */
