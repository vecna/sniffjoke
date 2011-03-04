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
#define MIN_SPLIT_PAYLOAD 1                         /*  1 bytes */
#define MIN_TCP_PAYLOAD   (MIN_SPLIT_PAYLOAD *2)    /*  2 bytes */
#define MAX_SPLIT_PKTS    5                         /*  5 pkts  */

private:
    pluginLogHandler pLH;

public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScrambles)
    {

        /*
         * due to the ratio between MIN_SPLIT_PAYLOAD and MIN_TCP_PAYLOAD
         * the hack will produce a min number of 2 pkts and a max of 5 pkt
         */
        uint32_t split_size = (origpkt.tcppayloadlen / MAX_SPLIT_PKTS) + ((origpkt.tcppayloadlen % MAX_SPLIT_PKTS) ? 1 : 0);
        split_size = split_size > MIN_SPLIT_PAYLOAD ? split_size : MIN_SPLIT_PAYLOAD;
        const uint8_t pkts_n = (origpkt.tcppayloadlen / split_size) + ((origpkt.tcppayloadlen % split_size) ? 1 : 0);
        const uint32_t carry = (origpkt.tcppayloadlen % split_size) ? (origpkt.tcppayloadlen % split_size) : split_size;

        const uint32_t starting_seq = ntohl(origpkt.tcp->seq);

        pLH.completeLog("packet size %d start_seq %u (sport %u), splitted in %d chunk of %d bytes",
                        origpkt.tcppayloadlen, starting_seq, ntohs(origpkt.tcp->source),
                        pkts_n, split_size);

        for (uint8_t pkts = 0; pkts < pkts_n; pkts++)
        {
            Packet * const pkt = new Packet(origpkt);

            pkt->tcp->seq = htonl(starting_seq + (pkts * split_size));

            uint32_t resizeAndCopy = 0;
            if (pkts < (pkts_n - 1)) /* first (pkt - 1) segments */
            {
                pkt->tcp->fin = 0;
                pkt->tcp->rst = 0;

                /* if the PUSH is present, it's keept only in the lasy data pkt */
                pkt->tcp->psh = 0;

                resizeAndCopy = split_size;
            }
            else /* last segment */
            {
                resizeAndCopy = carry;
            }

            pkt->tcppayloadResize(resizeAndCopy);
            memcpy(pkt->tcppayload, &origpkt.tcppayload[pkts * split_size], resizeAndCopy);

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
            pkt->choosableScramble = (availableScrambles & supportedScrambles);

            /* I was tempted to set it FINALHACK, but Sj supports fragment, lets see */
            upgradeChainFlag(pkt);

            pktVector.push_back(pkt);

            pLH.completeLog(" chunk %d of %d - (seq %u) TCP source port %u",
                            (pkts + 1), pkts_n, ntohl(pkt->tcp->seq), ntohs(pkt->tcp->source));
        }

        removeOrigPkt = true;
    }

    virtual bool Condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag != HACKUNASSIGNED)
            return false;

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

        /* the only acceptable Scramble is INNOCENT, because the hack is based on
         * overlap the fragment of the same packet */
        supportedScrambles = SCRAMBLE_INNOCENT;

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
