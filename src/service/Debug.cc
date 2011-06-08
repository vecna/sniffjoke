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

#include "Debug.h"

Debug::Debug(void) :
debuglevel(ALL_LEVEL),
logstream(stdout),
session_logstream(stdout),
packet_logstream(stdout)
{

}

void Debug::setLogstream(const char *lsf)
{
    logstream_file = lsf;
    logstream = NULL;
}

void Debug::setSessionLogstream(const char *lsf)
{
    session_logstream_file = lsf;
    session_logstream = NULL;
}

void Debug::setPacketLogstream(const char *lsf)
{
    packet_logstream_file = lsf;
    packet_logstream = NULL;
}

bool Debug::appendOpen(uint8_t thislevel, const char *fname, char *buf, FILE **previously)
{
    if (*previously == stdout)
        return true;

    if (*previously != NULL)
    {
        log(thislevel, __func__, "requested close of logfile %s (vars used: %s and level %d)",
            fname, fname, thislevel);
        fclose(*previously);
        *previously = NULL;
    }

    if (debuglevel >= thislevel)
    {
        if ((fname == NULL) || ((*previously = fopen(fname, "a+")) == NULL))
            return false;

        /* setbuffer(*previously, buf, DEBUGBUFFER); */
        setlinebuf(*previously);

        log(thislevel, __func__, "opened logfile %s successful with debug level %d", fname, debuglevel);
    }

    return true;
}

bool Debug::resetLevel(void)
{
    if (!appendOpen(ALL_LEVEL, logstream_file, logstream_buf, &logstream))
        return false;

    if (!appendOpen(SESSION_LEVEL, session_logstream_file, session_logstream_buf, &session_logstream))
        return false;

    if (!appendOpen(PACKET_LEVEL, packet_logstream_file, session_logstream_buf, &packet_logstream))
        return false;

    return true;
}

void Debug::log(uint8_t errorlevel, const char *funcname, const char *msg, ...)
{
    if (errorlevel <= debuglevel)
    {
        FILE *output_flow;

        if (logstream != NULL)
            output_flow = logstream;
        else
            output_flow = stderr;

        if (errorlevel == PACKET_LEVEL && packet_logstream != NULL)
            output_flow = packet_logstream;

        else if (errorlevel == SESSION_LEVEL && session_logstream != NULL)
            output_flow = session_logstream;

        /* the debug level used in development include function/pid/uid addictional infos */
        if (errorlevel == DEBUG_LEVEL)
            fprintf(output_flow, "%s %s %d/%d ", sj_clock_str, funcname, getpid(), getuid());
        else
            fprintf(output_flow, "%s ", sj_clock_str);

        va_list arguments;
        va_start(arguments, msg);
        vfprintf(output_flow, msg, arguments);
        va_end(arguments);

        fprintf(output_flow, "\n");
    }
}

void Debug::downgradeOpenlog(uid_t uid, gid_t gid)
{
    /* this should not be called when is not the root process to do */
    if (getuid() && getgid())
        return;

    if (logstream != NULL)
        if(fchown(fileno(logstream), uid, gid) == -1)
            RUNTIME_EXCEPTION("unable to change privileges to %d %d: %s", uid, gid, strerror(errno));

    if (packet_logstream != NULL)
        if(fchown(fileno(packet_logstream), uid, gid) == -1)
            RUNTIME_EXCEPTION("unable to change privileges to %d %d: %s", uid, gid, strerror(errno));

    if (session_logstream != NULL)
        if(fchown(fileno(session_logstream), uid, gid) == -1)
            RUNTIME_EXCEPTION("unable to change privileges to %d %d: %s", uid, gid, strerror(errno));
}

/* Class pluginLogHandler used by plugins for selective logging */
pluginLogHandler::pluginLogHandler(const char *sN, const char *LfN) :
selfName(sN)
{
    if ((logstream = fopen(LfN, "a+")) == NULL)
        RUNTIME_EXCEPTION("unable to open %s: %s", LfN, strerror(errno));

    /* at the moment is used this solution. soon, janus integration, will solve
     * every father/child/root/chroot/perm issue */
    if(fchmod(fileno(logstream),  0666) == -1)
        RUNTIME_EXCEPTION("unable to make plugin %s (%s) rw+uga: %s", selfName, LfN, strerror(errno));

    /* setbuffer(logstream, logstream_buf, DEBUGBUFFER); */
    setlinebuf(logstream);

    completeLog("opened file %s successful for handler %s", LfN, selfName);
}

pluginLogHandler::~pluginLogHandler(void)
{
    completeLog("requested logfile closing %s", selfName);
    fclose(logstream);
}

void pluginLogHandler::completeLog(const char *msg, ...)
{
    fprintf(logstream, "%s ", sj_clock_str);

    va_list arguments;
    va_start(arguments, msg);
    vfprintf(logstream, msg, arguments);
    fprintf(logstream, "\n");
    va_end(arguments);
}

void pluginLogHandler::simpleLog(const char *msg, ...)
{
    va_list arguments;
    va_start(arguments, msg);
    vfprintf(logstream, msg, arguments);
    fprintf(logstream, "\n");
    va_end(arguments);
}
