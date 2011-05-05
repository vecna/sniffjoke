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

#ifndef SJ_SNIFFJOKE_H
#define SJ_SNIFFJOKE_H

#include "Utils.h"
#include "UserConf.h"
#include "Process.h"
#include "NetIO.h"
#include "TCPTrack.h"
#include "TTLFocus.h"
#include "SessionTrack.h"
#include "OptionPool.h"
#include "PluginPool.h"
#include "config.h"

class SniffJoke
{
public:
    bool alive;
    SniffJoke(const struct sj_cmdline_opts &);
    ~SniffJoke(void);
    void run(void);

private:
    const sj_cmdline_opts &opts;

    auto_ptr<Process> proc;
    auto_ptr<NetIO> mitm;
    auto_ptr<TCPTrack> conntrack;

    /* after detach:
     *     service_pid in the root process [the pid of the user process]
     *                 in the user process [0]
     */
    pid_t service_pid;

    int admin_socket;
    int admin_socket_flags_blocking;
    int admin_socket_flags_nonblocking;

    /* used to copy structs for command I/O */
    uint8_t io_buf[HUGEBUF * 4];

    /* used to make public the singleton to the plugins */
    struct sjEnviron autoptrList;

    void updateClock(void);
    void setupDebug(void);
    void cleanDebug(void);
    void cleanServerRoot(void);
    void cleanServerUser(void);
    void setupAdminSocket(void);
    void handleAdminSocket(void);
    void createSjEnvironment(void);

    /* internalProtocol handling */
    uint8_t* handleCmd(const char *);

    /* single command management */
    void handleCmdStart(void);
    void handleCmdStop(void);
    void handleCmdQuit(void);
    void handleCmdSaveconf(void);
    void handleCmdStat(void);
    void handleCmdInfo(void);
    void handleCmdTTL(void);
    void handleCmdShowport(void);
    void handleCmdSet(const char *);
    void handleCmdDebuglevel(uint8_t);

    /* main function for build the answer */
    void writeSJStatus(uint8_t);
    void writeSJPortStat(uint8_t);
    void writeSJInfoDump(uint8_t);
    void writeSJTTLmap(uint8_t);
    void writeSJProtoError(void);

    /* called by writeSJ* functions = answer building */
    uint32_t appendSJStatus(uint8_t *, int32_t, uint32_t, uint16_t);
    uint32_t appendSJStatus(uint8_t *, int32_t, uint32_t, bool);
    uint32_t appendSJStatus(uint8_t *, int32_t, uint32_t, const char *);
    uint32_t appendSJPortBlock(uint8_t *, uint16_t, uint16_t, uint16_t);
    uint32_t appendSJSessionInfo(uint8_t *, const SessionTrack &);
    uint32_t appendSJTTLInfo(uint8_t *, const TTLFocus &);
};

#endif /* SJ_SNIFFJOKE_H */
