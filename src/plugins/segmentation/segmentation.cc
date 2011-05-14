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
 * this hack simply does a massive segmentation of a tcp packet;
 * this could help to bypass some simple sniffers and ids.
 * 
 * 
 * SOURCE: deduction, 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Plugin.h"

class segmentation : public Plugin
{
#define PLUGIN_NAME "TCP Segmentation"
#define PKT_LOG "plugin.segmentation.log"

#define MIN_SPLIT_PAYLOAD 500 /* bytes */
#define MIN_SPLIT_PKTS    2
#define MAX_SPLIT_PKTS    5
#define MIN_TCP_PAYLOAD   (MIN_SPLIT_PKTS * MIN_SPLIT_PAYLOAD)

private:

    pluginLogHandler pLH;

    PluginCache cache;

    static bool filter(const cacheRecord &record, const Packet &pkt)
    {
        const Packet &refpkt = record.cached_packet;
        const uint32_t realnextseq = ntohl(refpkt.tcp->seq) + refpkt.tcppayloadlen;

        return (refpkt.ip->daddr == pkt.ip->saddr &&
                refpkt.ip->saddr == pkt.ip->daddr &&
                pkt.proto == TCP &&
                refpkt.tcp->source == pkt.tcp->dest &&
                refpkt.tcp->dest == pkt.tcp->source &&
                pkt.tcp->ack == 1 &&
                realnextseq > ntohl(pkt.tcp->ack_seq));
    }

public:

    segmentation() :
    Plugin(PLUGIN_NAME, AGG_RARE),
    pLH(PLUGIN_NAME, PKT_LOG)
    {
    };

    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s plugin supports only INNOCENT scramble type", PLUGIN_NAME);
            return false;
        }

        /* the original is removed, and segments are inserted */
        supportedScrambles = SCRAMBLE_INNOCENT;

        pLH.completeLog("Initialized plugin!");

        return true;
    }

    virtual bool condition(const Packet & origpkt, uint8_t availableScrambles)
    {
        pLH.completeLog("verifing condition for id %d (sport %u) datalen %d total len %d",
                        origpkt.ip->id, ntohs(origpkt.tcp->source), origpkt.tcppayloadlen, origpkt.pbuf.size());

        if (origpkt.chainflag == FINALHACK)
            return false;

        if (origpkt.fragment == false &&
                origpkt.proto == TCP &&
                !origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin &&
                origpkt.tcppayload != NULL &&
                origpkt.tcppayloadlen >= MIN_TCP_PAYLOAD)
            return true;

        return false;
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        /*
         * due to the ratio: MIN_TCP_PAYLOAD = (MIN_SPLIT_PKTS * MIN_SPLIT_PAYLOAD)
         * the hack will produce pkts between a min of MIN_SPLIT_PKTS and a max of MAX_SPLIT_PKTS
         */
        uint8_t pkts_n = MIN_SPLIT_PKTS + random() % (MAX_SPLIT_PKTS - (MIN_SPLIT_PKTS - 1));
        uint32_t split_size = origpkt.tcppayloadlen / pkts_n;
        split_size = split_size > MIN_SPLIT_PAYLOAD ? split_size : MIN_SPLIT_PAYLOAD;
        pkts_n = (origpkt.tcppayloadlen / split_size) + ((origpkt.tcppayloadlen % split_size) ? 1 : 0);
        const uint32_t carry = (origpkt.tcppayloadlen % split_size) ? (origpkt.tcppayloadlen % split_size) : split_size;

        const uint32_t starting_seq = ntohl(origpkt.tcp->seq);

        const char *p;
        char saddr[MEDIUMBUF] = {0}, daddr[MEDIUMBUF] = {0};
        p = inet_ntoa(*((struct in_addr *) &(origpkt.ip->saddr)));
        strncpy(saddr, p, sizeof (saddr));
        p = inet_ntoa(*((struct in_addr *) &(origpkt.ip->daddr)));
        strncpy(daddr, p, sizeof (daddr));

        pLH.completeLog("packet %s:%u -> %s:%u size %d start_seq %x (sport %u), splitted in %d chunk of %d bytes",
                        saddr, ntohs(origpkt.tcp->source), daddr, ntohs(origpkt.tcp->dest),
                        origpkt.tcppayloadlen, starting_seq, ntohs(origpkt.tcp->source),
                        pkts_n, split_size);

        for (uint8_t pkts = 0; pkts < pkts_n; pkts++)
        {
            Packet * const pkt = new Packet(origpkt);

            pkt->randomizeID();

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

            pkt->source = PLUGIN;

            /*
             * the orig packet is removed, so the value of the position
             * has no particular importance for the hack
             *
             * by the way setting this to ANTICIPATION it's fundamental
             * to keep packets trasmission ordered, and here is the reason why:
             *
             * ok tcp has sequence number to handle the packet reorder correctly but
             * we do a massive fragmentation to fight ids so with disordered
             * packets we would have a too much degraded session due to FAST_RETRASMIT
             * and others tcp features.
             */
            pkt->position = ANTICIPATION;

            /* we keep the origpkt.wtf to permit this hack to segment both good and evil pkts */
            pkt->wtf = origpkt.wtf;

            /* useless, INNOCENT is never downgraded in last_pkt_fix */
            pkt->choosableScramble = (availableScrambles & supportedScrambles);

            /* I was tempted to set it FINALHACK, but Sj supports fragment, lets see */
            upgradeChainFlag(pkt);

            pktVector.push_back(pkt);

            pLH.completeLog("%d/%d chunk seq|%x sjPacketId %d size %d", 
                            (pkts + 1), pkts_n, ntohl(pkt->tcp->seq), pkt->SjPacketId, resizeAndCopy);
        }

        cache.add(origpkt);

        removeOrigPkt = true;
    }

    void mangleIncoming(Packet &pkt)
    {
        cacheRecord *record = cache.check(&filter, pkt);

        if (record != NULL)
        {
            const char *p;
            char saddr[MEDIUMBUF] = {0}, daddr[MEDIUMBUF] = {0};
            p = inet_ntoa(*((struct in_addr *) &(pkt.ip->saddr)));
            strncpy(saddr, p, sizeof (saddr));
            p = inet_ntoa(*((struct in_addr *) &(pkt.ip->daddr)));
            strncpy(daddr, p, sizeof (daddr));

            pLH.completeLog("requesting packet removal due to segmented ack: %s:%u -> %s:%u ack_seq|%x",
                            saddr, ntohs(pkt.tcp->source), daddr, ntohs(pkt.tcp->dest),
                            ntohl(pkt.tcp->ack_seq));

            removeOrigPkt = true;
        }
    }
};

extern "C" Plugin* createPluginObj()
{
    return new segmentation();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
