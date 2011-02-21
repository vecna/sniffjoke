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

#include "Hack.h"

uint32_t Hack::generateUniqPluginId(void)
{
    uint32_t retval = 1;

    for (uint32_t i = 0; i < strlen(hackName); i++)
    {
        retval *= ((hackName[i] % 7) + 1);
        retval += (hackName[i] % 8);
        retval /= ((hackName[i] % 4) + 1);
    }

    return retval;
}

bool Hack::hackCacheCheck(const Packet &oP, uint8_t cacheID, uint32_t *dataptr)
{
    uint32_t pluginID = generateUniqPluginId();
    vector<struct cacheRecord *>::iterator it;

    for (it = hackCache.begin(); it != hackCache.end(); it++)
    {
        cacheRecord &record = **it;
        if (pluginID == record.pluginID && record.cacheID == cacheID &&
                record.daddr == oP.ip->daddr && record.sport == oP.tcp->source)
        {
            memcpy(dataptr, &(record.cachedData), sizeof (dataptr));
            return true;
        }
    }

    return false;
}

void Hack::hackCacheAdd(const Packet &oP, uint8_t cacheID, uint32_t data)
{
    uint32_t pluginID = generateUniqPluginId();
    struct cacheRecord *newcache = new struct cacheRecord;

    newcache->cachedData = data;
    newcache->pluginID = pluginID;
    newcache->cacheID = cacheID;
    newcache->sport = oP.tcp->source;
    newcache->daddr = oP.ip->daddr;
    /* will be fixed in the future */
    newcache->addedtime = 0;

    hackCache.push_back(newcache);
}

void Hack::hackCacheDel(const Packet &oP, uint8_t cacheID)
{
    uint32_t pluginID = generateUniqPluginId();
    vector<struct cacheRecord *>::iterator it;

    for (it = hackCache.begin(); it != hackCache.end(); it++)
    {
        cacheRecord &record = **it;
        if (pluginID == record.pluginID && record.cacheID == cacheID &&
                record.daddr == oP.ip->daddr && record.sport == oP.tcp->source)
        {
            delete &record;
            hackCache.erase(it++);
            return;
        }
    }
}

/* overloaded without the ID usage */
bool Hack::hackCacheCheck(const Packet &oP, uint32_t *dataptr)
{
    return hackCacheCheck(oP, 0xff, dataptr);
}

void Hack::hackCacheAdd(const Packet &oP, uint32_t data)
{
    hackCacheAdd(oP, 0xff, data);
}

void Hack::hackCacheDel(const Packet &oP)
{
    hackCacheDel(oP, 0xff);
}


