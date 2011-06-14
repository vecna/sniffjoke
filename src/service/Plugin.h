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

#ifndef SJ_PLUGIN_H
#define SJ_PLUGIN_H

#include "Utils.h"
#include "Packet.h"

/* 
 *
 * Following this howto: http://www.faqs.org/docs/Linux-mini/C++-dlopen.html
 * we understood how to do a plugin and load it.
 * HackPacket classes are implemented as external modules and the programmer
 * shoulds implement condition and apply, constructor and distructor methods.
 *
 * At the end of every plugin code, it's is required to export two "C" symbols,
 * pointing to the constructor and the destructor method.
 *
 */

class cacheRecord
{
public:
    const Packet cached_packet;
    vector<unsigned char>cached_data;

    cacheRecord(const Packet& pkt) :
    cached_packet(pkt)
    {
    };

    cacheRecord(const Packet& pkt, const unsigned char* data, size_t data_size) :
    cached_packet(pkt),
    cached_data(data, data + data_size)
    {
    };
};

class PluginCache
{
    time_t timeout_len;
    time_t manage_timeout;
    vector<cacheRecord*> fm[2];
    vector<cacheRecord*> *first;
    vector<cacheRecord*> *second;

    /* called automagically */
    void manage(void);

public:

    PluginCache(time_t = PLUGINCACHE_EXPIRYTIME);
    ~PluginCache();

    /*
      we export the iterator as return to permit explicit cache removal;
      this is not a requirement for plugins, due to the mangage routine included in cacheCheck
     */
    cacheRecord* check(bool(*)(const cacheRecord &, const Packet &), const Packet &);
    cacheRecord* add(const Packet &);
    cacheRecord* add(const Packet &, const unsigned char*, size_t);
    void explicitDelete(struct cacheRecord *);
};

class Plugin
{
public:

    const char * const pluginName; /* plugin name as const string */
    uint8_t supportedScrambles; /* supported by the location, derived
                                   from plugin_enabler.conf.$location */
    const uint16_t pluginFrequency; /* plugin frequency, using the value  */
    bool removeOrigPkt; /* boolean to be set true if the plugin
                           needs to remove the original packet */

    vector<Packet *> pktVector; /* std vector of Packet* used for created packets */

    Plugin(const char *, uint16_t);

    judge_t pktRandomDamage(uint8_t, uint8_t);
    void upgradeChainFlag(Packet *);

    /* Plugin is an abstract class */
    virtual bool init(uint8_t, char *, struct sjEnviron *) = 0;
    virtual bool condition(const Packet &, uint8_t);
    virtual void apply(const Packet &, uint8_t);
    virtual void mangleIncoming(Packet &);
    virtual void reset(void);

    /* follow the utilities usable by the plugins */
    cacheRecord *verifyIfCache(bool(*)(const cacheRecord &, const Packet &), PluginCache *, const Packet &);
    bool inverseProportionality(uint32_t, uint32_t, uint32_t);

    /* filter used in caching, these are passed to cache.check and verifyIfCache */
    static bool tupleMatch(const cacheRecord &, const Packet &);
    static bool ackedseqMatch(const cacheRecord &, const Packet &);
};

#endif /* SJ_PLUGIN_H */
