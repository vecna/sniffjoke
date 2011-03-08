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
 * http://en.wikipedia.org/wiki/IPv4#Fragmentation
 *
 * this hack simply does a massive fragmentation of a ip packet (or fragment itself).
 * this could help to bypass some simple sniffers and ids.
 *
 * SOURCE: fragmentation historically is a pain in the ass for whom code firewall & sniffer
 * VERIFIED IN:
 * KNOW BUGS:
 */

#include "service/Plugin.h"

class fragmentation : public Plugin
{
#define PLUGIN_NAME "Fragmentation"
#define PKT_LOG "plugin.fragmentation.log"

#define MIN_SPLIT_PAYLOAD 8 /* bytes */
#define MIN_SPLIT_PKTS    2
#define MAX_SPLIT_PKTS    5
#define MIN_IP_PAYLOAD    (MIN_SPLIT_PKTS * MIN_SPLIT_PAYLOAD)

private:

    pluginLogHandler pLH;

public:

    fragmentation() :
    Plugin(PLUGIN_NAME, AGG_ALWAYS),
    pLH(PLUGIN_NAME, PKT_LOG)
    {
    }

    virtual bool initializePlugin(uint8_t configuredScramble)
    {
        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s plugin supports only INNOCENT scramble type", PLUGIN_NAME);
            return false;
        }

        supportedScrambles = SCRAMBLE_INNOCENT;

        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        pLH.completeLog("verifing condition for id %d datalen %d total len %d",
                        origpkt.ip->id, ntohs(origpkt.ip->tot_len), origpkt.pbuf.size());

        if (origpkt.chainflag == FINALHACK)
            return false;

        if (!(availableScrambles & supportedScrambles))
        {
            origpkt.SELFLOG("no scramble avalable for %s", PLUGIN_NAME);
            return false;
        }

        /*
         *  RFC 791 states:
         *
         * "Every internet module must be able to forward a datagram of 68
         *  octets without further fragmentation.  This is because an internet
         *  header may be up to 60 octets, and the minimum fragment is 8 octets."
         *
         */
        return (!(origpkt.ip->frag_off & htons(IP_DF)) &&
                origpkt.ippayloadlen >= MIN_IP_PAYLOAD);
    }

    virtual void applyPlugin(const Packet &origpkt, uint8_t availableScrambles)
    {
        /*
         * due to the ratio: MIN_IP_PAYLOAD = (MIN_SPLIT_PKTS * MIN_SPLIT_PAYLOAD)
         * the hack will produce pkts between a min of MIN_SPLIT_PKTS and a max of MAX_SPLIT_PKTS
         */
        uint8_t pkts_n = MIN_SPLIT_PKTS + random() % (MAX_SPLIT_PKTS - (MIN_SPLIT_PKTS - 1));
        uint32_t split_size = origpkt.ippayloadlen / pkts_n;
        split_size = split_size > MIN_SPLIT_PAYLOAD ? split_size : MIN_SPLIT_PAYLOAD;
        split_size = (split_size >> 3) << 3; /* we need an offset multiple */
        pkts_n = (origpkt.ippayloadlen / split_size) + ((origpkt.ippayloadlen % split_size) ? 1 : 0);
        const uint32_t carry = (origpkt.ippayloadlen % split_size) ? (origpkt.ippayloadlen % split_size) : split_size;

        vector<unsigned char> pbufcpy(origpkt.pbuf);
        vector<unsigned char>::iterator it = pbufcpy.begin() + origpkt.iphdrlen;

        pLH.completeLog("packet size %d, splitted in %d chunk of %d bytes",
                        ntohs(origpkt.ip->tot_len), pkts_n, split_size);

        uint16_t offset = ntohs(origpkt.ip->frag_off) & ~htons(~IP_DF | ~IP_MF);
        bool justfragmented = ntohs(origpkt.ip->frag_off) & htons(IP_MF);

        for (uint8_t pkts = 0; pkts < pkts_n; pkts++)
        {
            vector<unsigned char> pktbuf(pbufcpy.begin(), pbufcpy.begin() + origpkt.iphdrlen);

            struct iphdr *ip = (struct iphdr *) &(pktbuf[0]);

            if (pkts < (pkts_n - 1)) /* first (pkt - 1) segments */
            {
                /* common in my code */
                ip->id = htons(ntohs(ip->id) - 10 + (random() % 20));

                ip->tot_len = htons(origpkt.iphdrlen + split_size);
                ip->frag_off = htons(offset | IP_MF);
                pktbuf.insert(pktbuf.end(), it, it + split_size);
                offset += split_size >> 3;
                it += split_size;
            }
            else /* last segment */
            {
                /* marker useful when I feel drunk and confused by tcpdump */
                ip->id = 1;

                ip->tot_len = htons(origpkt.iphdrlen + carry);
                if (justfragmented)
                    ip->frag_off = htons(offset | IP_MF);
                else
                    ip->frag_off = htons(offset);

                pktbuf.insert(pktbuf.end(), it, it + carry);
            }

            Packet * const pkt = new Packet(&pktbuf[0], pktbuf.size());

            pkt->randomizeID();

            pkt->source = PLUGIN;

            /*
             * the orig packet is removed, so the value of the position
             * has no particular importance for the hack
             *
             * by the way setting this to ANTICIPATION it's fundamental
             * to keep packets trasmission ordered.
             */
            pkt->position = ANTICIPATION;

            /* we keep the origpkt.wtf to permit this hack to segment both good and evil pkts */
            pkt->wtf = origpkt.wtf;

            /* useless, INNOCENT is never downgraded in last_pkt_fix */
            pkt->choosableScramble = (availableScrambles & supportedScrambles);

            /* we need to force inheriet of chainflag due to packet creation */
            pkt->chainflag = origpkt.chainflag;

            upgradeChainFlag(pkt);

            pktVector.push_back(pkt);

            pLH.completeLog(" chunk %d of %d", (pkts + 1), pkts);
        }

        removeOrigPkt = true;

    }
};

extern "C" Plugin* createPluginObj()
{
    return new fragmentation();
}

extern "C" void deletePluginObj(Plugin *who)
{

    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
