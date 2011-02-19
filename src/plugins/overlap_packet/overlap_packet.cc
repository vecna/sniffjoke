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

#include "service/Hack.h"

class overlap_packet : public Hack
{
#define HACK_NAME "Overlap Packet"
#define PKT_LOG "plugin.overlap_packet.log"
#define MIN_PACKET_OVERTRY  400

private:
    pluginLogHandler pLH;

public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        /* the block split size must not create a last packet of 0 byte! */

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

        /* this tests: a valid packet with a lenght LESS THAN the real size sent by
         * the kernel, followed by the same packet of good dimension. seems that
         * windows uses the first received packet while unix the last received.
         */

        /* Is cached the amount of data cached in the first segment */
        uint32_t cachedData;
        Packet * const pkt = new Packet(origpkt);

        if(!(hackCacheCheck(origpkt, &cachedData)))
        {
            cachedData = (origpkt.datalen / 2);

            hackCacheAdd(origpkt, cachedData);

            pkt->tcppayloadRandomFill();
            memcpy(&pkt->payload[cachedData], &origpkt.payload[cachedData], 200);

            pLH.completeLog("2) injected packet (sport %u seq %u) length %d, %d random and the other good", 
                ntohs(pkt->tcp->source), ntohl(pkt->tcp->seq), 
                pkt->datalen, cachedData
            );

        }
        else 
        {
            hackCacheDel(origpkt);

            pkt->tcppayloadResize(cachedData);

            pLH.completeLog("1) original pkt size %d truncated of %d byte to %d (sport %u seq %u)", 
                origpkt.datalen, origpkt.datalen - cachedData, cachedData, 
                ntohs(pkt->tcp->source), ntohl(pkt->tcp->seq)
            );
            memcpy(pkt->payload, origpkt.payload, cachedData);

            pkt->tcp->psh = 0;

        }

        pkt->position = ANTICIPATION;
        pkt->wtf = INNOCENT;
        pktVector.push_back(pkt);
        removeOrigPkt = true;
    }

    /* the only acceptable Scramble is INNOCENT, because the hack is based on
     * overlap the fragment of the same packet */
    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        return (origpkt.payload != NULL && origpkt.datalen > MIN_PACKET_OVERTRY);
    }

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s plugin supports only INNOCENT scramble type", hackName);
            return false;
        }

        supportedScramble = SCRAMBLE_INNOCENT;

        return true;
    }

    overlap_packet(bool forcedTest) :
    Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_RARE),
    pLH(HACK_NAME, PKT_LOG)
    {
    }
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{
    return new overlap_packet(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
