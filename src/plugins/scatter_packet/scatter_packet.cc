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
 * This hack scatter one single packet of large payload in a lot of little
 * chunck;
 * this hack represent the base for developing:
 *  1) chained hacks
 * 
 * SOURCE: deduction, 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Hack.h"

#define MIN_BLOCK_SPLIT     28
#define MIN_SCRAMBLE_PACKET MIN_BLOCK_SPLIT*3

#define SCATTER_PKT_LOG     "scatterPacket.plugin.log"

class scatter_packet : public Hack
{
private:
    pluginLogHandler *pLH;

#define HACK_NAME "Scatter Packet"
public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        const uint32_t starting_seq = ntohl(origpkt.tcp->seq);

        /*
         * block_split between MIN_BLOCK_SPLIT and ((2 * MIN_BLOCK_SPLIT) - 1);
         * having MIN_SCRAMBLE_PACKET = MIN_BLOCK_SPLIT*3 we will have at least two pkts
         */
        const uint32_t block_split = MIN_BLOCK_SPLIT + (random() % MIN_BLOCK_SPLIT);
        const uint8_t pkts = (origpkt.datalen / block_split) + ((origpkt.datalen % block_split) ? 1 : 0);

        pLH->completeLog("packet size %d start_seq %u (sport %u), splitted in %d chunk of %d bytes",
                         origpkt.datalen, starting_seq, ntohs(origpkt.tcp->source),
                         pkts, block_split);

        for (uint8_t i = 0; i < pkts; i++)
        {
            Packet * const pkt = new Packet(origpkt);
            uint32_t thisdatalen;

            if (i < (pkts - 1)) /* first (pkt - 1) segments */
            {
                thisdatalen = block_split;

                pkt->tcppayloadResize(thisdatalen);

                memcpy(pkt->payload, &origpkt.payload[i * block_split], thisdatalen);

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
                thisdatalen = (origpkt.datalen % block_split) ? (origpkt.datalen % block_split) : block_split;

                pkt->tcppayloadResize(thisdatalen);

                memcpy(pkt->payload, &origpkt.payload[i * block_split], thisdatalen);

                pkt->tcp->seq = htonl(starting_seq + (i * block_split));

                /* marker useful when I feel drunk and confused by tcpdump */
                pkt->ip->id = 1;

            }

            pLH->completeLog(" %d) of %d - chunk data %d (seq %u) TCP source port %u",
                             (i + 1), pkts, thisdatalen, ntohl(pkt->tcp->seq), ntohs(pkt->tcp->source));

            pkt->position = ANTICIPATION;
            pkt->wtf = INNOCENT;

            pktVector.push_back(pkt);
        }

        removeOrigPkt = true;
    }

    /* the only acceptable Scramble is INNOCENT, because the hack is based on
     * overlap the fragment of the same packet */
    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        pLH->completeLog("verifing condition for id %d (sport %u) datalen %d total len %d",
                         origpkt.ip->id, ntohs(origpkt.tcp->source), origpkt.datalen, origpkt.pbuf.size());

        if ((origpkt.payload != NULL) && (origpkt.datalen >= MIN_SCRAMBLE_PACKET))
            return true;

        return false;
    }

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        pLH = new pluginLogHandler(HACK_NAME, SCATTER_PKT_LOG);

        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s hack supports only INNOCENT scramble type", HACK_NAME);
            return false;
        }
        return true;
    }

    scatter_packet(bool forcedTest) : Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_RARE)
    {
    };
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{
    return new scatter_packet(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
