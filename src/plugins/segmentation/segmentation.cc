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
 */

/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 *
 * this hack simply do a massive segment fragmentation of tcp packet.
 * this could help to bypass some simple sniffers and ids.
 * 
 * 
 * SOURCE: deduction, 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Hack.h"

class segmentation : public Hack
{
#define HACK_NAME "TCP Segmentation"
#define PKT_LOG "plugin.segmentation.log"
#define MIN_BLOCK_SPLIT 28
#define MIN_TCP_PAYLOAD MIN_BLOCK_SPLIT*2

private:
    pluginLogHandler pLH;

public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        /*
         * block_split between MIN_BLOCK_SPLIT and ((2 * MIN_BLOCK_SPLIT) - 1);
         * having MIN_SCRAMBLE_PACKET = MIN_BLOCK_SPLIT*2 we will have at least two segments
         */
        const uint32_t block_split = MIN_BLOCK_SPLIT + (random() % MIN_BLOCK_SPLIT);
        const uint32_t carry = (origpkt.tcppayloadlen % block_split) ? (origpkt.tcppayloadlen % block_split) : block_split;
        const uint8_t pkts = (origpkt.tcppayloadlen / block_split) + ((origpkt.tcppayloadlen % block_split) ? 1 : 0);

        const uint32_t starting_seq = ntohl(origpkt.tcp->seq);

        pLH.completeLog("packet size %d start_seq %u (sport %u), splitted in %d chunk of %d bytes",
                         origpkt.tcppayloadlen, starting_seq, ntohs(origpkt.tcp->source),
                         pkts, block_split);

        for (uint8_t i = 0; i < pkts; i++)
        {
            Packet * const pkt = new Packet(origpkt);

            if (i < (pkts - 1)) /* first (pkt - 1) segments */
            {

                pkt->tcppayloadResize(block_split);

                memcpy(pkt->tcppayload, &origpkt.tcppayload[i * block_split], block_split);

                pkt->tcp->seq = htonl(starting_seq + (i * block_split));

                pkt->tcp->fin = 0;
                pkt->tcp->rst = 0;

                /* if the PUSH is present, it's keept only in the lasy data pkt */
                pkt->tcp->psh = 0;

                /* common in my code */
                pkt->ip->id = htons(ntohs(pkt->ip->id) - 10 + (random() % 20));

            }
            else /* last segment */
            {
                pkt->tcppayloadResize(carry);

                memcpy(pkt->tcppayload, &origpkt.tcppayload[i * block_split], carry);

                pkt->tcp->seq = htonl(starting_seq + (i * block_split));

                /* marker useful when I feel drunk and confused by tcpdump */
                pkt->ip->id = 1;

            }

            /*
             * the orig packet is removed, so the value of the position
             * has no particular importance for the hack
             *
             * by the way setting this to ANTICIPATION it's fundamental
             * to keep packets trasmission ordered, and her is the reason why:
             *
             * ok tcp has sequence number to handle the packet reorder correctly but
             * we do a massive fragmentation to fight ids so with disordered
             * packets we would have a too much degraded session due to FAST_RETRASMIT
             * and others tcp features.
             */
            pkt->position = ANTICIPATION;

            pkt->wtf = INNOCENT;

            /* useless, INNOCENT is never downgraded in last_pkt_fix */
            pkt->choosableScramble = (availableScramble & supportedScramble);

            pktVector.push_back(pkt);

            pLH.completeLog(" chunk %d of %d - (seq %u) TCP source port %u",
                (i + 1), pkts, ntohl(pkt->tcp->seq), ntohs(pkt->tcp->source));
        }

        removeOrigPkt = true;
    }

    /* the only acceptable Scramble is INNOCENT, because the hack is based on
     * overlap the fragment of the same packet */
    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        pLH.completeLog("verifing condition for id %d (sport %u) datalen %d total len %d",
                         origpkt.ip->id, ntohs(origpkt.tcp->source), origpkt.tcppayloadlen, origpkt.pbuf.size());

        if (origpkt.fragment == false &&
            origpkt.proto == TCP &&
            origpkt.tcppayload != NULL &&
            origpkt.tcppayloadlen >= MIN_TCP_PAYLOAD)
            return true;

        return false;
    }

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s plugin supports only INNOCENT scramble type", HACK_NAME);
            return false;
        }

        supportedScramble = SCRAMBLE_INNOCENT;

        return true;
    }

    segmentation(bool forcedTest) :
            Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_RARE),
            pLH(HACK_NAME, PKT_LOG)
    {
    };
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{
    return new segmentation(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
