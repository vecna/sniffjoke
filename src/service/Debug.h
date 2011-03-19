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

#ifndef SJ_DEBUG_H
#define SJ_DEBUG_H

#include "Utils.h"

#define DEBUGBUFFER 65536 /* 64k */

class Debug
{
private:

    friend class SniffJoke;
    friend class Process;

    uint8_t debuglevel;
    const char* logstream_file;
    const char* session_logstream_file;
    const char* packet_logstream_file;
    FILE *logstream;
    FILE *session_logstream;
    FILE *packet_logstream;
    char logstream_buf[DEBUGBUFFER];
    char session_logstream_buf[DEBUGBUFFER];
    char packet_logstream_buf[DEBUGBUFFER];

    void setLogstream(const char *lsf);
    void setSessionLogstream(const char *lsf);
    void setPacketLogstream(const char *lsf);
    bool appendOpen(uint8_t thislevel, const char *fname, char* buf, FILE **previously);
    void downgradeOpenlog(uid_t, gid_t);
    bool resetLevel(void);

public:
    Debug(void);

    void log(uint8_t, const char *, const char *, ...);

    uint8_t level(void)
    {
        return debuglevel;
    };
};

/* Facility to support debug and dumping by the plugins */
class pluginLogHandler
{
private:
    const char *selfName;
    FILE *logstream;
    char logstream_buf[DEBUGBUFFER];
public:
    pluginLogHandler(const char *, const char *);
    ~pluginLogHandler(void);
    void completeLog(const char *, ...);
    void simpleLog(const char *, ...);
};


#define LOG_ALL(...)     debug.log(ALL_LEVEL, __func__, __VA_ARGS__)
#define LOG_VERBOSE(...) debug.log(VERBOSE_LEVEL, __func__, __VA_ARGS__)
#define LOG_DEBUG(...)   debug.log(DEBUG_LEVEL, __func__, __VA_ARGS__)
#define LOG_SESSION(...) debug.log(SESSION_LEVEL, __func__, __VA_ARGS__)
#define LOG_PACKET(...)  debug.log(PACKET_LEVEL, __func__, __VA_ARGS__)


/* global debug object defined into Debug.cc and exported by this module */
extern Debug debug;

#endif /* SJ_DEBUG_H */
