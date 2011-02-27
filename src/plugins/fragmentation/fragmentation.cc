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
 * this hack simply do a massive fragmentation of ip packet (or fragment itself).
 * this could help to bypass some simple sniffers and ids.
 *
 * SOURCE: fragmentation historically is a pain in the ass for whom code firewall & sniffer
 * VERIFIED IN:
 * KNOW BUGS:
 */

#include "service/Hack.h"

class fragmentation : public Hack
{
#define HACK_NAME "Fragmentation"
#define PKT_LOG "plugin.fragmentation.log"
#define MIN_BLOCK_SPLIT 48
#define MIN_IP_PAYLOAD MIN_BLOCK_SPLIT*2

private:
    pluginLogHandler pLH;

public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        /*
         * block_split between MIN_BLOCK_SPLIT and ((2 * MIN_BLOCK_SPLIT) - 1);
         * having MIN_SCRAMBLE_PACKET = MIN_BLOCK_SPLIT*3 we will have at least two fragments
         */
        const uint32_t block_split = ((MIN_BLOCK_SPLIT + (random() % MIN_BLOCK_SPLIT)) >> 3) << 3;
        uint16_t ip_payload_len = ntohs(origpkt.ip->tot_len) - origpkt.iphdrlen;
        uint16_t carry = (ip_payload_len % block_split) ? (ip_payload_len % block_split) : block_split;
        const uint8_t pkts = (ip_payload_len / block_split) + ((ip_payload_len % block_split) ? 1 : 0);

        vector<unsigned char> pbufcpy(origpkt.pbuf);
        vector<unsigned char>::iterator it = pbufcpy.begin() + origpkt.iphdrlen;

        pLH.completeLog("packet size %d, splitted in %d chunk of %d bytes",
                        ntohs(origpkt.ip->tot_len), pkts, block_split);

        uint16_t offset = ntohs(origpkt.ip->frag_off) & ~htons(IP_MF);
        bool justfragmented = ntohs(origpkt.ip->frag_off) & htons(IP_MF);

        for (uint8_t i = 0; i < pkts; i++)
        {
            vector<unsigned char> pktbuf(pbufcpy.begin(), pbufcpy.begin() + origpkt.iphdrlen);

            struct iphdr *ip = (struct iphdr *) &(pktbuf[0]);

            if (i < (pkts - 1)) /* first (pkt - 1) segments */
            {
                /* common in my code */
                ip->id = htons(ntohs(ip->id) - 10 + (random() % 20));

                ip->tot_len = htons(origpkt.iphdrlen + block_split);
                ip->frag_off = htons(offset | IP_MF); /* set more fragment bit */
                pktbuf.insert(pktbuf.end(), it, it + block_split);
                offset += block_split >> 3;
                it += block_split;
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

            /*
             * the orig packet is removed, so the value of the position
             * has no particular importance for the hack
             *
             * by the way setting this to ANTICIPATION it's fundamental
             * to keep packets trasmission ordered.
             */
            pkt->position = ANTICIPATION;

            pkt->wtf = INNOCENT;

            /* useless, INNOCENT is never downgraded in last_pkt_fix */
            pkt->choosableScramble = (availableScramble & supportedScramble);

            pktVector.push_back(pkt);

            pLH.completeLog(" chunk %d of %d", (i + 1), pkts);
        }

        removeOrigPkt = true;

    }

    virtual void mangleIncoming(const Packet &incompkt)
    {
        /* used as testing */
        incompkt.ip->id = 1;
    }

    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        pLH.completeLog("verifing condition for id %d datalen %d total len %d",
                        origpkt.ip->id, ntohs(origpkt.ip->tot_len), origpkt.pbuf.size());

        if (!(availableScramble & supportedScramble))
        {
            origpkt.SELFLOG("no scramble avalable for %s", HACK_NAME);
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
                origpkt.iphdrlen + ((ntohs(origpkt.ip->tot_len) - origpkt.iphdrlen) / 2) >= 68);
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

    fragmentation(bool forcedTest) :
            Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_ALWAYS),
            pLH(HACK_NAME, PKT_LOG)
    {
    }
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{

    return new fragmentation(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{

    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
