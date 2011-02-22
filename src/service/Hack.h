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

class cacheRecord
{
public:
    time_t access_timestamp;
    const Packet cached_packet;
    void *cached_data;

    cacheRecord(const Packet& pkt) :
    access_timestamp(sj_clock),
    cached_packet(pkt),
    cached_data(NULL)
    {
    };

    cacheRecord(const Packet& pkt, const void* data, size_t data_size) :
    access_timestamp(sj_clock),
    cached_packet(pkt)
    {
        cached_data = malloc(data_size);
        memcpy(cached_data, data, data_size);
    };
};

class Hack
{
public:

    uint8_t supportedScramble; /* supported by the location, derived
                                  from plugin_enabler.conf.$location */
    const char *hackName; /* hack name as const string */
    const uint16_t hackFrequency; /* hack frequency, using the value  */
    bool removeOrigPkt; /* boolean to be set true if the hack
                           needs to remove the original packet */

    vector<Packet*> pktVector; /* std vector of Packet* used for created hack packets */
    vector<cacheRecord*> hackCache;

    judge_t pktRandomDamage(uint8_t scrambles)
    {
        if (ISSET_TTL(scrambles) && RANDOMPERCENT(75))
            return PRESCRIPTION;
        if (ISSET_MALFORMED(scrambles) && RANDOMPERCENT(80))
            return MALFORMED;
        return GUILTY;
    }

    Hack(const char* hackName, uint16_t hackFrequency) :
    hackName(hackName),
    hackFrequency(hackFrequency),
    removeOrigPkt(false)
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

    vector<cacheRecord *>::iterator cacheCheck(bool(*filter)(const Packet &, const Packet &), const Packet &);
    vector<cacheRecord *>::iterator cacheCreate(const Packet &);
    vector<cacheRecord *>::iterator cacheCreate(const Packet &, void* data, size_t data_size);
    void cacheDelete(vector<struct cacheRecord *>::iterator it);

};

#endif /* SJ_HACK_H */
