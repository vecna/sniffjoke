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
#include <stdexcept>

using namespace std;


#include <stdint.h>
#include <unistd.h>

#include "hardcodedDefines.h"

enum size_buf_t
{
    SMALLBUF = 64,
    MEDIUMBUF = 256,
    LARGEBUF = 1024,
    HUGEBUF = 4096,
    GARGANTUABUF = 4096 * 4
};

/* loglevels & log classess */
#include "Debug.h"

#define SUPPRESS_LEVEL      0
#define ALL_LEVEL           1
#define ALL_LEVEL_NAME      "default"
#define VERBOSE_LEVEL       2
#define VERBOSE_LEVEL_NAME  "verbose"
#define DEBUG_LEVEL         3
#define DEBUG_LEVEL_NAME    "debug"
#define SESSION_LEVEL       4
#define SESSION_LEVEL_NAME  "sessions"
#define PACKET_LEVEL        5
#define PACKET_LEVEL_NAME   "packets"
#define TESTING_LEVEL       6
#define TESTING_LEVEL_NAME  "testing"

/*
 * there is a single clock in sniffjoke, global and
 * manteined by the NetIO module (network_io)
 */
extern time_t sj_clock;

/* those are the value used for track port strength of TCP coverage */
#define PORTSNUMBER             65536

#define SCRAMBLE_TTL            1
#define SCRAMBLE_TTL_STR        "PRESCRIPTION"
#define SCRAMBLE_CHECKSUM       2
#define SCRAMBLE_CHECKSUM_STR   "GUILTY"
#define SCRAMBLE_MALFORMED      4
#define SCRAMBLE_MALFORMED_STR  "MALFORMED"
#define SCRAMBLE_INNOCENT       8
#define SCRAMBLE_INNOCENT_STR   "INNOCENT"

#define ISSET_TTL(byte)         (byte & SCRAMBLE_TTL)
#define ISSET_CHECKSUM(byte)    (byte & SCRAMBLE_CHECKSUM)
#define ISSET_MALFORMED(byte)   (byte & SCRAMBLE_MALFORMED)
#define ISSET_INNOCENT(byte)    (byte & SCRAMBLE_INNOCENT)

int snprintfScramblesList(char *str, size_t size, uint8_t scramblesList);

#define RANDOMPERCENT(percent) ( (uint32_t)random() % 100 <= percent)
void init_random(void);
void* memset_random(void *, size_t);

#define SELFLOG(...) selflog(__func__, __VA_ARGS__)
#define RUNTIME_EXCEPTION(...) throw runtime_exception(__func__, __FILE__, __LINE__, __VA_ARGS__)
std::runtime_error runtime_exception(const char *, const char *, int32_t, const char *, ...);


#endif /* SJ_UTILS_H */
