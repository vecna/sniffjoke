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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <sstream>

#include <unistd.h>

#include "hardcoded-defines.h"
#include "Debug.h"

enum size_buf_t {
		SMALLBUF = 64,
		MEDIUMBUF = 256,
		LARGEBUF = 1024,
		HUGEBUF = 4096,
		GARGANTUABUF = 4096 * 4
};

/* not used ATM */
#define SUPPRESS_LOG		1

/* loglevels */
#define ALL_LEVEL		2
#define ALL_LEVEL_NAME		"default"
#define VERBOSE_LEVEL		3
#define VERBOSE_LEVEL_NAME	"verbose"
#define DEBUG_LEVEL		4
#define DEBUG_LEVEL_NAME	"debug"
#define SESSION_DEBUG		5
#define SESSION_DEBUG_NAME	"hacks"
#define PACKETS_DEBUG		6
#define PACKETS_DEBUG_NAME      "packets"

#define SJ_RUNTIME_EXCEPTION()	throw sj_runtime_exception(__func__, __FILE__, __LINE__)
std::runtime_error sj_runtime_exception(const char* func, const char* file, long line);
void* memset_random(void *s, size_t n);
void sigtrap(int signal);

#endif /* SJ_UTILS_H */
