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

#include "Plugin.h"

PluginCache::PluginCache(time_t timeout) :
cacheTimeout(timeout)
{
    LOG_DEBUG("");
}

PluginCache::~PluginCache()
{
    LOG_DEBUG("");

    for (vector<cacheRecord *>::iterator it = begin(); it != end(); it = erase(it))
        delete *it;
}

vector<cacheRecord *>::iterator PluginCache::cacheCheck(bool(*filter)(const cacheRecord &, const Packet &), const Packet &pkt)
{
    for (vector<cacheRecord *>::iterator it = begin(); it != end();)
    {
        cacheRecord &record = **it;
        if (filter(record, pkt))
        {
            record.access_timestamp = sj_clock; /* update the access timestamp */
            return it;
        }

        if (record.access_timestamp < sj_clock - cacheTimeout)
        {
            it = cacheDelete(it); /* the ++ is done internally by the cacheDelete
                                     to keep the iterator valid */
        }
        else
        {
            it++;
        }
    }

    return end();
}

vector<cacheRecord *>::iterator PluginCache::cacheAdd(const Packet &pkt)
{
    cacheRecord *newrecord = new cacheRecord(pkt);
    push_back(newrecord);
    return end() - 1;
}

vector<cacheRecord *>::iterator PluginCache::cacheAdd(const Packet &pkt, const unsigned char *data, size_t data_size)
{
    cacheRecord *newrecord = new cacheRecord(pkt, data, data_size);
    push_back(newrecord);
    return end() - 1;
}

vector<cacheRecord *>::iterator PluginCache::cacheDelete(vector<struct cacheRecord *>::iterator it)
{
    delete *it;
    return erase(it);
}

Plugin::Plugin(const char* pluginName, uint16_t pluginFrequency) :
pluginName(pluginName),
pluginFrequency(pluginFrequency),
removeOrigPkt(false)
{
}

judge_t Plugin::pktRandomDamage(uint8_t scrambles)
{
    if (ISSET_TTL(scrambles) && RANDOM_PERCENT(75))
        return PRESCRIPTION;
    if (ISSET_MALFORMED(scrambles) && RANDOM_PERCENT(80))
        return MALFORMED;
    return GUILTY;
}

bool Plugin::init(uint8_t configuredScramble)
{
    return true;
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
        pkt->chainflag = FINALHACK;
    }
}
