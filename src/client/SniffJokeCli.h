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

#ifndef SJ_SNIFFJOKECLI_H
#define SJ_SNIFFJOKECLI_H

#include "service/Utils.h"

#include <cstdio>
#include <stdint.h>

#include <event.h>

using namespace std;

#define SJCTL_VERSION           "0.4.3"

#define SJCTL_DEFAULT_TIMEOUT   500
#define SJ_OK                   0
#define SJ_ERROR                1
#define SJ_TIMEOUT              2

struct command
{
    const char *cmd;
    int related_args;
};

class SniffJokeCli
{
private:
    const char *serveraddr;
    uint16_t serverport;
    const char *cmd_buffer;

    uint32_t fillingSpaces(uint16_t);
    uint32_t fillingSpace(uint16_t, uint16_t);
    void resolveWeight(char *, size_t, uint32_t);

    bool parse_SjinternalProto(uint8_t *, uint32_t);
    bool printSJStat(const uint8_t *, uint32_t);
    bool printSJPort(const uint8_t *, uint32_t);
    bool printSJError(const uint8_t *, uint32_t);
    bool printSJSessionInfo(const uint8_t *, uint32_t);
    bool printSJTTL(const uint8_t *, uint32_t);

public:
    int status;

    int sock;

    struct event ev_read;
    struct event ev_signal;
    struct timeval timeout;

    uint8_t received_data[HUGEBUF * 4];
    uint32_t progressive_recvl;


    SniffJokeCli(const char *, uint16_t, uint32_t);
    int32_t send_command(const char *cmdstring);
};

#endif /* SJ_SNIFFJOKECLI_H */
