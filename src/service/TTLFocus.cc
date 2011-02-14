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

#include "TTLFocus.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

TTLFocus::TTLFocus(const Packet &pkt) :
access_timestamp(sj_clock),
next_probe_time(sj_clock),
probe_timeout(0),
status(TTL_BRUTEFORCE),
rand_key(random()),
puppet_port(0),
sent_probe(0),
received_probe(0),
daddr(pkt.ip->daddr),
ttl_estimate(0xff),
ttl_synack(0),
probe_dummy(pkt)
{
    probe_dummy.iphdrResize(sizeof (struct iphdr));
    probe_dummy.tcphdrResize(sizeof (struct tcphdr));
    probe_dummy.tcppayloadResize(0);
    probe_dummy.tcp->fin = 0;
    probe_dummy.tcp->syn = 1;
    probe_dummy.tcp->rst = 0;
    probe_dummy.tcp->psh = 0;
    probe_dummy.tcp->ack = 0;
    probe_dummy.tcp->urg = 0;
    probe_dummy.tcp->res1 = 0;
    probe_dummy.tcp->res2 = 0;

    selectPuppetPort();

    SELFLOG("");
}

TTLFocus::TTLFocus(const struct ttlfocus_cache_record& cpy) :
access_timestamp(cpy.access_timestamp),
next_probe_time(sj_clock),
status(TTL_KNOWN),
rand_key(random()),
puppet_port(0),
sent_probe(0),
received_probe(0),
daddr(cpy.daddr),
ttl_estimate(cpy.ttl_estimate),
ttl_synack(cpy.ttl_synack),
probe_dummy(cpy.probe_dummy, sizeof (cpy.probe_dummy))
{
    selectPuppetPort();

    SELFLOG("");
}

TTLFocus::~TTLFocus()
{
    SELFLOG("");
}

void TTLFocus::selectPuppetPort()
{
    uint16_t realport = probe_dummy.tcp->source;
    puppet_port = (realport + random()) % 32767 + 1;
    if (puppet_port > realport - PUPPET_MARGIN
            && puppet_port < realport + PUPPET_MARGIN)
        puppet_port = (puppet_port + (random() % 2) ? -PUPPET_MARGIN : +PUPPET_MARGIN) % 32767 + 1;
}

void TTLFocus::selflog(const char *func, const char *format, ...) const
{
    if (debug.level() == SUPPRESS_LEVEL)
        return;

    char loginfo[LARGEBUF];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(loginfo, sizeof (loginfo), format, arguments);
    va_end(arguments);

    const char *status_name = "";

    switch (status)
    {
    case TTL_KNOWN: status_name = "KNOWN";
        break;
    case TTL_BRUTEFORCE: status_name = "BRUTEFORCE";
        break;
    case TTL_UNKNOWN: status_name = "UNKNOWN";
        break;
    }

    LOG_SESSION("%s (%s) [%s] m_sent %d, m_recv %d ttl_estimate %u synackttl %u %s",
                func, inet_ntoa(*((struct in_addr *) &(daddr))), status_name, sent_probe,
                received_probe, ttl_estimate, ttl_synack, loginfo
                );
}

TTLFocusMap::TTLFocusMap()
{
    LOG_VERBOSE("");

    load();
}

TTLFocusMap::~TTLFocusMap()
{
    LOG_VERBOSE("");

    dump();

    for (TTLFocusMap::iterator it = begin(); it != end();)
    {
        delete &(*it->second);
        erase(it++);
    }
}

/* return a ttlfocus given a packet; return a new ttlfocus if no one exists */
TTLFocus& TTLFocusMap::get(const Packet &pkt)
{
    TTLFocus *ttlfocus;

    /* check if the key it's already present */
    TTLFocusMap::iterator it = find(pkt.ip->daddr);
    if (it != end()) /* on hit: return the ttlfocus object. */
        ttlfocus = &(*it->second);
    else /* on miss: create a new ttlfocus and insert it into the map */
        ttlfocus = &(*insert(pair<uint32_t, TTLFocus*>(pkt.ip->daddr, new TTLFocus(pkt))).first->second);

    /* update access timestamp using global clock */
    ttlfocus->access_timestamp = sj_clock;
    return *ttlfocus;
}

struct ttlfocus_timestamp_comparison
{

    bool operator() (TTLFocus *i, TTLFocus * j)
    {
        return ( i->access_timestamp < j->access_timestamp);
    }
} ttlfocusTimestampComparison;

void TTLFocusMap::manage()
{
    if (!(sj_clock % TTLFOCUSMAP_MANAGE_ROUTINE_TIMER))
    {
        for (TTLFocusMap::iterator it = begin(); it != end();)
        {
            if ((*it).second->access_timestamp + TTLFOCUS_EXPIRYTIME < sj_clock)
                erase(it++);
            else
                ++it;
        }
    }

    uint32_t map_size = size();
    uint32_t index;
    if (map_size > TTLFOCUSMAP_MEMORY_THRESHOLD)
    {
        /*
         * We are forced to make a map cleanup.
         * In solve this critical condition we decide to reset half
         * of the map, and to do the best selection we reorder
         * the map by the access timestamp.
         * The complexity cost of this operation is O(NLogN)
         * due to the sort algorithm.
         * This is the worst case; (others operations are linear
         */
        TTLFocus** tmp = new TTLFocus*[map_size];

        index = 0;
        for (TTLFocusMap::iterator it = begin(); it != end(); ++it)
            tmp[index++] = it->second;

        clear();

        sort(tmp, tmp + map_size, ttlfocusTimestampComparison);

        index = 0;
        do
        {
            insert(pair<uint32_t, TTLFocus*>((tmp[index])->daddr, tmp[index]));
        }
        while (++index != TTLFOCUSMAP_MEMORY_THRESHOLD / 2);

        do
            delete tmp[index];
        while (++index != map_size);

        delete[] tmp;
    }
}

void TTLFocusMap::load()
{
    FILE *loadstream = NULL;
    uint32_t records_num = 0;
    struct ttlfocus_cache_record tmp;
    int ret;

    LOG_ALL("loading ttlfocusmap from %s", FILE_TTLFOCUSMAP);

    if ((loadstream = fopen(FILE_TTLFOCUSMAP, "r")) == NULL)
    {
        LOG_ALL("unable to access network cache: sniffjoke will start without it");
        return;
    }

    while ((ret = fread(&tmp, sizeof (struct ttlfocus_cache_record), 1, loadstream)) == 1)
    {
        ++records_num;
        TTLFocus *ttlfocus = new TTLFocus(tmp);
        insert(pair<uint32_t, TTLFocus*>(ttlfocus->daddr, ttlfocus));
    }

    fclose(loadstream);

    LOG_ALL("load completed: %u records loaded", records_num);
}

void TTLFocusMap::dump()
{
    FILE *dumpstream = NULL;
    uint32_t undumped = 0, records_num = 0;

    LOG_ALL("dumping ttlfocusmap to %s", FILE_TTLFOCUSMAP);

    if ((dumpstream = fopen(FILE_TTLFOCUSMAP, "w")) == NULL)
    {
        LOG_ALL("unable to write network cache");
        return;
    }

    for (TTLFocusMap::iterator it = begin(); it != end(); ++it)
    {
        TTLFocus *tmp = &(*it->second);

        /* we saves only with TTL_KNOWN status */
        if (tmp->status != TTL_KNOWN)
        {
            ++undumped;
            continue;
        }

        struct ttlfocus_cache_record cache_record;
        memset(&cache_record, 0, sizeof (struct ttlfocus_cache_record));
        cache_record.access_timestamp = tmp->access_timestamp;
        cache_record.daddr = tmp->daddr;
        cache_record.ttl_estimate = tmp->ttl_estimate;
        cache_record.ttl_synack = tmp->ttl_synack;

        /*
         * copy the probe_dummy.pbuf vector into the cache record;
         * a ttlprobe packet is always 40 bytes (min iphdr + min tcphdr),
         * ipopts, tcpopts, and payload are stripped of on creation
         */
        memcpy(cache_record.probe_dummy, &(tmp->probe_dummy.pbuf[0]), 40);

        if (fwrite(&cache_record, sizeof (struct ttlfocus_cache_record), 1, dumpstream) != 1)
        {
            LOG_ALL("unable to dump ttlfocus: %s", strerror(errno));
            return;
        }

        ++records_num;
    }

    fclose(dumpstream);

    LOG_ALL("ttlfocusmap dump completed with %u records dumped, %u where incomplete.", records_num, undumped);
}
