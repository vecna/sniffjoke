/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *
 *   Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
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

#include "Plugin.h"

PluginCache::PluginCache(time_t timeout) :
timeout_len(timeout),
manage_timeout(sj_clock + timeout),
first(&fm[0]),
second(&fm[1])
{
    LOG_DEBUG("");
}

PluginCache::~PluginCache()
{
    LOG_DEBUG("");

    for (vector<cacheRecord *>::iterator it = first->begin(); it != first->end(); it = first->erase(it))
        delete *it;

    for (vector<cacheRecord *>::iterator it = second->begin(); it != second->end(); it = second->erase(it))
        delete *it;
}

cacheRecord* PluginCache::check(bool(*filter)(const cacheRecord &, const Packet &), const Packet &pkt)
{
    manage();

    for (vector<cacheRecord *>::iterator it = first->begin(); it != first->end(); ++it)
    {
        if (filter(**it, pkt))
        {
            cacheRecord *record = *it;
            /* update entry timeout moving it to the freshest vector */
            first->erase(it);
            second->push_back(record);
            return record;
        }
    }

    for (vector<cacheRecord *>::iterator it = second->begin(); it != second->end(); ++it)
    {
        if (filter(**it, pkt))
            return *it;
    }

    return NULL;
}

cacheRecord* PluginCache::add(const Packet &pkt)
{
    cacheRecord *newrecord = new cacheRecord(pkt);
    second->push_back(newrecord);
    return newrecord;
}

cacheRecord* PluginCache::add(const Packet &pkt, const unsigned char *data, size_t data_size)
{
    cacheRecord *newrecord = new cacheRecord(pkt, data, data_size);
    second->push_back(newrecord);
    return newrecord;
}

void PluginCache::explicitDelete(struct cacheRecord *record)
{
    for (vector<cacheRecord *>::iterator it = first->begin(); it != first->end(); ++it)
    {
        if (*it == record)
        {
            delete *it;
            first->erase(it);
            return;
        }
    }

    for (vector<cacheRecord *>::iterator it = second->begin(); it != second->end(); ++it)
    {
        if (*it == record)
        {
            delete *it;
            second->erase(it);
            return;
        }
    }
}

void PluginCache::manage(void)
{
    if (manage_timeout > sj_clock - timeout_len)
        return;

    for (vector<cacheRecord *>::iterator it = first->begin(); it != first->end(); it = first->erase(it))
        delete *it;

    vector<struct cacheRecord *> *tmp = first;
    first = second;
    second = tmp;

    manage_timeout = sj_clock + timeout_len;
}

Plugin::Plugin(const char* pluginName, uint16_t pluginFrequency) :
pluginName(pluginName),
pluginFrequency(pluginFrequency),
removeOrigPkt(false)
{
}

/*
 * availableScrambles is passed in the plugin application, is choose 
 * related by the avalability in the sniffjoke status
 *
 * supportedScrambles is the declared usage in the startup
 */
judge_t Plugin::pktRandomDamage(uint8_t availableScrambles, uint8_t supportedScrambles)
{
    uint8_t scrambles = (availableScrambles & supportedScrambles);
    char availStr[MEDIUMBUF], supportStr[MEDIUMBUF], andedStr[MEDIUMBUF];

    snprintfScramblesList(availStr, MEDIUMBUF, availableScrambles);
    snprintfScramblesList(supportStr, MEDIUMBUF, supportedScrambles);
    snprintfScramblesList(andedStr, MEDIUMBUF, scrambles);

    if (ISSET_TTL(scrambles) && random_percent(70))
    {
        LOG_PACKET("%s %s: avail [%s] init [%s] both [%s], choosed PRESCRIPTION",
                   __func__, pluginName, availStr, supportStr, andedStr);

        return PRESCRIPTION;
    }
    if (ISSET_MALFORMED(scrambles) && random_percent(95))
    {
        LOG_PACKET("%s %s: avail [%s] init [%s] both [%s], choosed MALFORMED",
                   __func__, pluginName, availStr, supportStr, andedStr);
        return MALFORMED;
    }

    LOG_PACKET("%s %s: avail [%s] init [%s] both [%s], choosed GUILTY",
               __func__, pluginName, availStr, supportStr, andedStr);

    return GUILTY;
}

bool Plugin::condition(const Packet &, uint8_t availableScrambles)
{
    return true;
}

void Plugin::apply(const Packet &, uint8_t availableScrambles)
{
    return;
}

void Plugin::mangleIncoming(Packet &pkt)
{
}

void Plugin::reset(void)
{
    removeOrigPkt = false;
    pktVector.clear();
}

void Plugin::upgradeChainFlag(Packet *pkt)
{
    switch (pkt->chainflag)
    {
    case HACKUNASSIGNED:
        pkt->chainflag = REHACKABLE;
        break;
    case REHACKABLE:
        pkt->chainflag = FINALHACK;
        break;
    case FINALHACK:
        LOG_ALL("Warning: a non hackable-again packet has requested an increment status: check packet_id %u",
                pkt->SjPacketId);
    }
}

/* easy interface for cache handling inside an extended Plugin class,
 * you need to register as private plugins own "cache" onject and pass them, it
 * work more or less like the "get" and "find" differencies in the Pool */
cacheRecord *Plugin::verifyIfCache( bool(*pktFilter)(const cacheRecord &, const Packet &), 
                                    PluginCache *localCache, const Packet &origpkt)
{
    cacheRecord *ret = localCache->check(pktFilter, origpkt);

    /* if not present, need to be created a new entry */
    if (ret == NULL)
    {
        uint32_t firstCachedPkt = 1;

        localCache->add(origpkt, (const unsigned char*) &firstCachedPkt, sizeof (firstCachedPkt));
    }

    return ret;
}

/************
 *
 * As explained in PluginList.txt, at the moment exists three kind of different macrotype of plugins,
 * every of these three kind, will require different method in supports 
 *
 ************/

/* ___ forcedClosing section ___
 * this is used as cache filter, aiming to match */
bool Plugin::tupleMatch(const cacheRecord &record, const Packet &pkt)
{
    const Packet &refpkt = record.cached_packet;

    return (refpkt.ip->daddr == pkt.ip->daddr &&
            refpkt.tcp->source == pkt.tcp->source &&
            refpkt.tcp->dest == pkt.tcp->dest);
}

/* ___ forcedClosing section ___
 * this is used for increase the probability af a matched packet, to be send early in the session */
bool Plugin::inverseProportionality(uint32_t pkts, uint32_t min_inj_pkts, uint32_t max_inj_pkts)
{
    if (pkts < min_inj_pkts)
        return true;

    if (pkts > max_inj_pkts)
        return false;

    return (random_percent(100 - (pkts * max_inj_pkts)));
}

/* ___ forcedClosing section ___ */


/* ___ payldBreakin section ___ */
bool Plugin::ackedseqMatch(const cacheRecord &record, const Packet &pkt)
{
    const Packet &refpkt = record.cached_packet;
    uint32_t expectedAck = *((uint32_t *)(&record.cached_data[0]));

    /* is used to check if a sequence sent is being ACKed */
    return (refpkt.ip->daddr == pkt.ip->saddr && refpkt.tcp->dest == pkt.tcp->source &&
            refpkt.tcp->dest == pkt.tcp->source && expectedAck == pkt.tcp->ack_seq);
}

/* ___ payldBreakin section ___ */

/* ___ badSync section ___ */
/* ___ badSync section ___ */

