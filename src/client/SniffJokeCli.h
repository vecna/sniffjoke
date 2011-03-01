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

#include <csignal>
#include <cstdio>
#include <memory>

#include <stdint.h>
#include "service/Packet.h"
#include "service/portConfParsing.h"
#include "service/internalProtocol.h"

using namespace std;

#define SJ_CLI_VERSION	"0.4.0"

#define DEFAULT_ADDRESS	"127.0.0.1"
#define DEFAULT_PORT	8844
#define DEFAULT_TIMEOUT	500

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
    uint32_t ms_timeout;
    const char *cmd_buffer;
    bool parse_SjinternalProto(uint8_t *, int32_t);
    bool printSJStat(uint8_t *, int32_t);
    bool printSJPort(uint8_t *, int32_t);
    bool printSJError(uint8_t *, int32_t);
    bool printSJSessionInfo(uint8_t*, uint32_t);
    bool printSJTTL(uint8_t *, uint32_t);

    char *fillWithSpace(uint16_t);
    char *fillWithSpace(uint16_t, uint16_t);
    char *resolveWeight(uint32_t);

public:
    SniffJokeCli(char *, uint16_t, uint32_t);
    void send_command(const char *cmdstring);
};

#endif /* SJ_SNIFFJOKECLI_H */
