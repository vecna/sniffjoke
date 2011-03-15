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

/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 * 
 * fake close is used because a sniffer could read a FIN like a session closing
 * tcp-flag, and stop the session monitoring/reassembly.
 *
 * SOURCE: phrack, deduction 
 * VERIFIED IN:
 * KNOW BUGS: fastweb network (italian wire provider), should not support this hack 
 * 	      because the HAG close the session at the first valid RST exiting
 * 	      from your box.
 */

#include "service/Plugin.h"

class fake_close_rst : public Plugin
{
#define PLUGIN_NAME "Fake RST"
#define PKT_LOG "plugin.fake_close_rst.log"
#define MIN_INJECTED_PKTS    4
#define MAX_INJECTED_PKTS    10

private:

    pluginLogHandler pLH;

    PluginCache cache;

    /* define the cache filter: we need to get info about the session tuple */
    static bool filter(const cacheRecord &record, const Packet &pkt)
    {
        const Packet &refpkt = record.cached_packet;

        return (refpkt.ip->daddr == pkt.ip->daddr &&
                refpkt.tcp->source == pkt.tcp->source &&
                refpkt.tcp->dest == pkt.tcp->dest);
    }

    bool inverseProportionality(uint32_t pkts)
    {
        if (pkts < MIN_INJECTED_PKTS)
            return true;

        if (pkts > MAX_INJECTED_PKTS)
            return false;

        return (RANDOM_PERCENT(100 - (pkts * MAX_INJECTED_PKTS)));
    }

public:

    fake_close_rst() :
    Plugin(PLUGIN_NAME, AGG_TIMEBASED20S),
    pLH(PLUGIN_NAME, PKT_LOG)
    {
    };

    virtual bool init(uint8_t configuredScramble)
    {
        supportedScrambles = configuredScramble;
        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        pLH.completeLog("verifing condition for id %d datalen %d total len %d",
                        origpkt.ip->id, ntohs(origpkt.ip->tot_len), origpkt.pbuf.size());

        if (origpkt.chainflag == FINALHACK)
            return false;

        /* preliminar condition */
        bool ret = origpkt.fragment == false &&
                origpkt.proto == TCP &&
                !origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin;

        if (!ret)
            return false;

        uint32_t *previouslyInjected;
        vector<cacheRecord *>::iterator it = cache.cacheCheck(&filter, origpkt);

        if (it == cache.end())
        {
            uint32_t firstCached = 1;

            cache.cacheAdd(origpkt, (const unsigned char*) &firstCached, sizeof (firstCached));

            pLH.completeLog("cache created for %s:%u",
                            inet_ntoa(*((struct in_addr *) &(origpkt.ip->daddr))), ntohs(origpkt.tcp->dest));
        }
        else
        {
            /* an hack like Fake RST will be useful few times, not for all the
             * connections: we are keeping a cache record to count every injected RST and after
             * a randomic number (between a min of 4 and 12), the RST is not injected again */
            previouslyInjected = (uint32_t*)&((*it)->cached_data[0]);

            /* we use the pointer to updat the cached data directly */
            ++(*previouslyInjected);

            ret = inverseProportionality(*previouslyInjected);

            pLH.completeLog("cache present for %s:%u value of %d condition return %s",
                            inet_ntoa(*((struct in_addr *) &(origpkt.ip->daddr))), ntohs(origpkt.tcp->dest),
                            *previouslyInjected, ret ? "TRUE" : "FALSE");
        }

        return true;
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->randomizeID();

        pkt->tcp->psh = 0;
        pkt->tcp->rst = 1;
        pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) - pkt->tcppayloadlen + 1);

        pkt->tcppayloadResize(0);

        pkt->source = PLUGIN;

        pkt->position = ANTICIPATION;

        pkt->wtf = pktRandomDamage(availableScrambles & supportedScrambles);
        pkt->choosableScramble = (availableScrambles & supportedScrambles);

        pkt->chainflag = FINALHACK;

        pktVector.push_back(pkt);
    }
};

extern "C" Plugin* createPluginObj()
{
    return new fake_close_rst();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
