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

#ifndef SJ_HACK_H
#define SJ_HACK_H

#include "Packet.h"
#include "UserConf.h" /* for ISSET_* #defines */

#include <vector>

using namespace std;

/* 
 * HackPacket - pure virtual methods 
 *
 * Following this howto: http://www.faqs.org/docs/Linux-mini/C++-dlopen.html
 * we understood how to do a plugin and load it.
 * HackPacket classes are implemented as external modules and the programmer
 * shoulds implement Condition and createHack, constructor and distructor methods.
 *
 * At the end of every plugin code, it's is required to export two "C" symbols,
 * pointing to the constructor and the destructor method.
 *
 */

class Hack
{
private:
    struct cacheRecord 
    {
        time_t addedtime;
        uint32_t cachedData;

        /* packet identification */
        uint32_t seq;
        uint16_t sport;
        uint32_t daddr; 
        uint32_t pluginID;
    };
    vector<struct cacheRecord> hackCache;

public:
    uint32_t generateUniqPluginId(void)
    {
        uint32_t retval = 1;

        for(uint32_t i = 0; i < strlen(hackName); i++)
            retval *= ( (hackName[i] % 7) + 1 );

        return retval;
    }

    bool hackCacheCheck(const Packet &oP, uint32_t *dataptr)
    {
        uint32_t pluginID = generateUniqPluginId();
        vector<struct cacheRecord>::iterator it;

        for(it = hackCache.begin(); it != hackCache.end(); it++)
        {
            if(pluginID == it->pluginID && it->seq == oP.tcp->seq && 
                it->daddr == oP.ip->daddr && it->sport == oP.tcp->source)
            {
                memcpy(dataptr, &(it->cachedData), sizeof(uint32_t));
                return true;
            }
        }

        return false;
    }

    void hackCacheAdd(const Packet &oP, uint32_t data)
    {
        uint32_t pluginID = generateUniqPluginId();
        struct cacheRecord newcache;

        newcache.cachedData = data;
        newcache.pluginID = pluginID;
        newcache.sport = oP.tcp->source;
        newcache.daddr = oP.ip->daddr;
        newcache.seq = oP.tcp->seq;
        /* will be fixed in the future */
        newcache.addedtime = 0;

        hackCache.push_back(newcache);
        // hackCache.insert(hackCache.begin(), newcache, hackCache.end() );
    }

    void hackCacheDel(const Packet &oP)
    {
        uint32_t pluginID = generateUniqPluginId();
        vector<struct cacheRecord>::iterator it;

        for(it = hackCache.begin(); it != hackCache.end(); it++)
        {
            if(pluginID == it->pluginID && it->seq == oP.tcp->seq && 
                it->daddr == oP.ip->daddr && it->sport == oP.tcp->source)
            {
                hackCache.erase(it);
                return;
            }
        }
    }

    uint8_t supportedScramble; /* supported by the location, derived
                                  from plugin_enabler.conf.$location */
    const char *hackName; /* hack name as const string */
    const uint16_t hackFrequency; /* hack frequency, using the value  */
    bool removeOrigPkt; /* boolean to be set true if the hack
                           needs to remove the original packet */

    vector<Packet*> pktVector; /* std vector of Packet* used for created hack packets */

    judge_t pktRandomDamage(uint8_t scrambles)
    {
        if (ISSET_TTL(scrambles) && RANDOMPERCENT(75))
            return PRESCRIPTION;
        if (ISSET_MALFORMED(scrambles) && RANDOMPERCENT(80))
            return MALFORMED;
        return GUILTY;
    }

    Hack(const char* hackName, uint16_t hackFrequency, bool removeOrigPkt = false) :
        hackName(hackName),
        hackFrequency(hackFrequency),
        removeOrigPkt(removeOrigPkt)
    {
    };

    virtual void createHack(const Packet &, uint8_t availableScramble) = 0;

    virtual bool Condition(const Packet &, uint8_t availableScramble)
    {
        return true;
    };

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        return true;
    };
};

#endif /* SJ_HACK_H */
