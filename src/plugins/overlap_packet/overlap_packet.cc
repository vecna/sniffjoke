/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011 vecna <vecna@delirandom.net>
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
 *   this research is dedicated to: http://www.youtube.com/watch?v=63FbXbJEmIs
 */

/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 *
 * This hack overlap one fake data sent before a real one;
 * did the remote kernel keep the first or the earliest ?
 * seems that windows and unix have different behaviour!
 * 
 * SOURCE: 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Plugin.h"

class overlap_packet : public Plugin
{
#define PLUGIN_NAME "Overlap Packet"
#define PKT_LOG "plugin.overlap_packet.log"
#define MIN_PACKET_OVERTRY 600

#define SEQINFO 1

private:

    pluginLogHandler pLH;

    PluginCache cache;

    static bool filter(const cacheRecord &record, const Packet &pkt)
    {

        const Packet &refpkt = record.cached_packet;

        return (refpkt.ip->daddr == pkt.ip->daddr &&
                refpkt.tcp->source == pkt.tcp->source &&
                refpkt.tcp->seq == pkt.tcp->seq);
    }

public:

    overlap_packet() :
    Plugin(PLUGIN_NAME, AGG_RARE),
    pLH(PLUGIN_NAME, PKT_LOG)
    {
    }

    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s plugin supports only INNOCENT scramble type", pluginName);
            return false;
        }

        supportedScrambles = SCRAMBLE_INNOCENT;

        return true;
    }

    /* the only acceptable Scramble is INNOCENT, because the hack is based on
     * overlap the fragment of the same packet */
    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag != HACKUNASSIGNED)
            return false;

        return (origpkt.fragment == false &&
                origpkt.proto == TCP &&
                origpkt.tcppayload != NULL &&
                origpkt.tcppayloadlen > MIN_PACKET_OVERTRY);
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        /* 
         * TODO -- 
         * with posticipation under Linux and Window the FIRST packet is accepted, and
         * the sniffer will keep the first or the last depends from the sniffing tech
         *
                pkt->position = POSTICIPATION;
         *
         * Here is explored the usabilility of some TCPOPT making the packets unable
         * to be accepted (PAWS with expired timestamp) --- TODO
         */

        /* the test: a valid packet with a lenght LESS THAN the real size sent by
         * the kernel, followed by the same packet of good dimension. seems that
         * windows uses the first received packet while unix the last one.
         */

        Packet * const pkt = new Packet(origpkt);

        pkt->randomizeID();

        /* is cached the amount of data cached in the first segment */
        uint32_t sentData;

        cacheRecord *record = cache.check(&filter, origpkt);

        if (record == NULL)
        {
            sentData = (origpkt.tcppayloadlen / 2);

            cache.add(origpkt, (const unsigned char*) &sentData, sizeof(sentData));

            pkt->tcppayloadResize(sentData);
            pkt->tcp->psh = 0;

            pLH.completeLog("1) original pkt size %d truncated of %d byte to %d (sport %u seq %u)",
                            origpkt.tcppayloadlen, origpkt.tcppayloadlen - sentData, sentData,
                            ntohs(pkt->tcp->source), ntohl(pkt->tcp->seq)
                            );
        }
        else
        {

            sentData = *(uint32_t*)&(record->cached_data[0]);

            cache.explicitDelete(record);

            memset_random(pkt->tcppayload, sentData);

            pLH.completeLog("2) injected packet size %d, first %d random (sport %u seq %u)",
                            pkt->tcppayloadlen, sentData,
                            ntohs(pkt->tcp->source), ntohl(pkt->tcp->seq)
                            );
        }

        pkt->source = PLUGIN;

        pkt->position = ANTICIPATION;
        pkt->wtf = INNOCENT;

        upgradeChainFlag(pkt);

        pktVector.push_back(pkt);

        removeOrigPkt = true;
    }
};

extern "C" Plugin* createPluginObj()
{

    return new overlap_packet();
}

extern "C" void deletePluginObj(Plugin *who)
{

    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
