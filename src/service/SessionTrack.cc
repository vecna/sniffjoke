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

#include "hardcodedDefines.h"
/* defined at the bottom of hardcodedDefines.h */
#ifdef HEAVY_SESSION_DEBUG
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "SessionTrack.h"

SessionTrack::SessionTrack(const Packet &pkt) :
access_timestamp(0),
daddr(pkt.ip->daddr),
packet_number(0),
injected_pktnumber(0)
{
    if (pkt.proto == TCP)
    {
        proto = IPPROTO_TCP;
        sport = pkt.tcp->source;
        dport = pkt.tcp->dest;
    }
    else /* pkt.proto == UDP */
    {
        proto = IPPROTO_UDP;
        sport = pkt.udp->source;
        dport = pkt.udp->source;
    }

    SELFLOG("New session created from Packet ID #%d", pkt.SjPacketId);
}

SessionTrack::~SessionTrack(void)
{
    SELFLOG("");

#ifdef HEAVY_SESSION_DEBUG
#define SESSIONLOG_PREFIX   "sessionLog/"

    mkdir(SESSIONLOG_PREFIX, 0770);

    char fname[MEDIUMBUF];
    snprintf(fname, MEDIUMBUF, "%s%s", SESSIONLOG_PREFIX, inet_ntoa(*((struct in_addr *) &daddr)));

    FILE *sessionLog = fopen(fname, "a+");
    if (sessionLog == NULL)
        RUNTIME_EXCEPTION("unable to open %s:%s", fname, strerror(errno));

    char sj_clock_str[MEDIUMBUF];
    strftime(sj_clock_str, sizeof (sj_clock_str), "%F %T", localtime(&access_timestamp));
    fprintf(sessionLog, "%s\t%d:%d\t#%d, inj #%d\n",
            sj_clock_str, ntohs(sport), ntohs(dport), packet_number, injected_pktnumber);

    fclose(sessionLog);
#endif
}

void SessionTrack::selflog(const char *func, const char *format, ...) const
{
    if (debug.level() == SUPPRESS_LEVEL)
        return;

    char loginfo[LARGEBUF];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(loginfo, sizeof (loginfo), format, arguments);
    va_end(arguments);

    LOG_SESSION("%s %s S|-:%u D|%s:%d #pkts|%d #injs|%d %s",
                func, proto == IPPROTO_TCP ? "TCP" : "UDP",
                ntohs(sport),
                inet_ntoa(*((struct in_addr *) &daddr)), ntohs(dport),
                packet_number, injected_pktnumber,
                loginfo
                );
}

bool SessionTrackKey::operator<(SessionTrackKey comp) const
{
    if (proto < comp.proto)
        return true;
    else if (proto > comp.proto)
        return false;
    else
    {
        if (daddr < comp.daddr)
            return true;
        else if (daddr > comp.daddr)
            return false;
        else
        {
            if (sport < comp.sport)
                return true;
            else if (sport > comp.sport)
                return false;
            else
            {
                if (dport < comp.dport)
                    return true;
                else
                    return false;
            }
        }
    }
}

SessionTrackMap::SessionTrackMap(void) :
manage_timeout(sj_clock)
{
    LOG_DEBUG("");
}

SessionTrackMap::~SessionTrackMap(void)
{
    LOG_DEBUG("");

    for (SessionTrackMap::iterator it = begin(); it != end();)
    {
        delete &(*it->second);
        erase(it++);
    }
}

/* return a sessiontrack given a packet; return a new sessiontrack if no one exists */
SessionTrack& SessionTrackMap::get(const Packet &pkt)
{
    SessionTrack *sessiontrack;

    /* create map key */
    SessionTrackKey key;
    key.daddr = pkt.ip->daddr;
    if (pkt.proto == TCP)
    {
        key.proto = IPPROTO_TCP;
        key.sport = pkt.tcp->source;
        key.dport = pkt.tcp->dest;
    }
    else /* (pkt.proto == UDP) */
    {
        key.proto = IPPROTO_UDP;
        key.sport = pkt.udp->source;
        key.dport = pkt.udp->dest;
    }

    /* check if the key it's already present */
    SessionTrackMap::iterator it = find(key);
    if (it != end()) /* on hit: return the sessiontrack object. */
        sessiontrack = it->second;
    else /* on miss: create a new sessiontrack and insert it into the map */
        sessiontrack = insert(pair<SessionTrackKey, SessionTrack*>(key, new SessionTrack(pkt))).first->second;

    /* update access timestamp using global clock */
    sessiontrack->access_timestamp = sj_clock;

    return *sessiontrack;
}

void SessionTrackMap::manage(void)
{
    /* timeout check */
    if (manage_timeout < sj_clock - SESSIONTRACKMAP_MANAGE_ROUTINE_TIMER)
    {
        manage_timeout = sj_clock; /* update the next manage timeout */
        for (SessionTrackMap::iterator it = begin(); it != end();)
        {
            if ((*it).second->access_timestamp + SESSIONTRACK_EXPIRYTIME < sj_clock)
            {
                delete &(*it->second);
                erase(it++);
            }
            else
            {
                it++;
            }
        }
    }

    /* size check */
    uint32_t map_size = size();
    uint32_t index;
    if (map_size > SESSIONTRACKMAP_MEMORY_THRESHOLD)
    {
        /*
         * we are forced to make a map cleanup.
         * to solve this critical condition we decide to reset half
         * of the map, and to do the best selection we reorder
         * the map by the access timestamp.
         * the complexity cost of this operation is O(NLogN)
         * due to the sort algorithm.
         * this is the worst case; (others operations are linear)
         */
        SessionTrack** tmp = new SessionTrack*[map_size];

        index = 0;
        for (SessionTrackMap::iterator it = begin(); it != end(); ++it)
            tmp[index++] = it->second;

        clear();

        sort(tmp, tmp + map_size, sessiontrackTimestampComparison);

        index = 0;
        do
        {
            const SessionTrackKey key = {tmp[index]->daddr, tmp[index]->sport, tmp[index]->dport};
            insert(pair<SessionTrackKey, SessionTrack *>(key, tmp[index]));
        }
        while (++index != SESSIONTRACKMAP_MEMORY_THRESHOLD / 2);

        do
            delete tmp[index];
        while (++index != map_size);

        delete[] tmp;
    }
}
