/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011, 2010 vecna <vecna@delirandom.net>
 *                            evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include "hardcodedDefines.h"

#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <vector>

using namespace std;

#include <stdint.h>
#include <unistd.h>

/* required by fchmod - used for plugin logging in Debug.cc */
#include <sys/stat.h>

#include "Debug.h"

/*
 * there is a single clock in sniffjoke;
 * it global and defined/initialized/updated by Sniffjoke.cc
 */
extern time_t sj_clock;
extern char sj_clock_str[MEDIUMBUF];

#define ISSET_TTL(byte)         (byte & SCRAMBLE_TTL)
#define ISSET_CHECKSUM(byte)    (byte & SCRAMBLE_CHECKSUM)
#define ISSET_MALFORMED(byte)   (byte & SCRAMBLE_MALFORMED)
#define ISSET_INNOCENT(byte)    (byte & SCRAMBLE_INNOCENT)
#define RANDOM_IPOPT            ((random() % (LAST_IPOPT - FIRST_IPOPT )) + FIRST_IPOPT + 1)
#define RANDOM_TCPOPT           ((random() % (LAST_TCPOPT - FIRST_TCPOPT )) + FIRST_TCPOPT + 1)

/* std::runtime_error runtime_exception(const char *, const char *, uint32_t, const char *, ...); */
std::runtime_error runtime_exception(const char *, const char *, ...);

string execOSCmd(string cmd);
void init_random(void);
void* memset_random(void *, size_t);
int snprintfScramblesList(char *str, size_t size, uint8_t scramblesList);
bool random_percent(int32_t percent);

#define SELFLOG(...) selflog(__func__, __VA_ARGS__)

/* #define RUNTIME_EXCEPTION(...) throw runtime_exception(__func__, __FILE__, __LINE__, __VA_ARGS__) */
#define RUNTIME_EXCEPTION(...) throw runtime_exception(__func__, __VA_ARGS__)

/* 
 * this struct is the SniffJoke executing environment, it contains pointer to 
 * the main singleton instanced classess, and an sjEnviron is used for share
 * these pointer with the external loaded plugin.
 *
 * Is declared here, as void *, to (a)void: ‘BlahBlah’ was not declared in this scope
 */
struct sjEnviron
{
    /* therse three is declared as private in SniffJoke class */
    void * instanced_proc;
    void * instanced_mitm;
    void * instanced_ct;

    /* those five are global in the software */
    void * instanced_ucfg;
    void * instanced_ttl;
    void * instanced_sex;
    void * instanced_itopts;
    void * instanced_plugins;
};

#endif /* SJ_UTILS_H */
