/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                            evilaliv3 <giovanni.pellerano@evilaliv3.org>
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
 * A reset must be ignored if the ack value is more than last_ack_seq + window,
 * this is a path due to the denial of service named 
 * "Slipping in the window: TCP Reset attacks", linked below
 * this is another ack working in INNOCENT mode, not with GUILTY/PRESCRIPTION
 *
 * SOURCE: deduction, analysis of the DoS [ http://kerneltrap.org/node/3072 ]
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 *
 */

#include "service/Plugin.h"

class valid_rst_fake_seq : public Plugin
{
#define PLUGIN_NAME "valid offseq RST "
#define PKT_LOG "plugin.valid_offseq_rst.log"
#define MIN_INJECTED_PKTS    4
#define MAX_INJECTED_PKTS    10

private:
    pluginLogHandler pLH;

   /* every hack in "forcedClosing" will be useful "few times in a session", not for the
    * entire duration of the connections: for this reason is kept a cache record to count every 
    * time a condition is returned "true"
    *
    * MIN_INJECTED_PKTS mean the minimum packets possibile, between MIN < x < MAX, the probability
    * to be true the condition use an inverted probability, until reach MAX, than will never be 
    * injected again.
    *
    * this is implemented in the condition check and the useful generic method are implemented
    * in Plugin class, explanation useful will be found in ../PluginList.txt
    */
    PluginCache OFFRSTcache;

public:

    valid_rst_fake_seq() :
    Plugin(PLUGIN_NAME, AGG_PACKETS30PEEK),
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

        supportedScrambles = SCRAMBLE_INNOCENT;

        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag == FINALHACK || origpkt.proto != TCP || origpkt.fragment == true)
            return false;

        pLH.completeLog("verifing condition for ip.id %d Sj#%u (dport %u) datalen %d total len %d",
                        ntohs(origpkt.ip->id), origpkt.SjPacketId, ntohs(origpkt.tcp->dest), 
                        origpkt.tcppayloadlen, origpkt.pbuf.size());

        /* preliminar condition, TCP and fragment already checked */
        bool ret = (!origpkt.tcp->syn && !origpkt.tcp->rst && !origpkt.tcp->fin );

        if (!ret)
            return false;

        /* cache checking, using the methods provide in the section 'forcedClosing' of Plugin.cc */
        cacheRecord* matchRecord;

        if((matchRecord = verifyIfCache(&(tupleMatch), &OFFRSTcache, origpkt)) != NULL)
        {
            uint32_t *injectedYet = (uint32_t*)&(matchRecord->cached_data[0]);

            /* if is present, inverseProp, return true with decreasing probability up to MAX_INJ */
            ret = inverseProportionality(*injectedYet, MIN_INJECTED_PKTS, MAX_INJECTED_PKTS);

            if(ret)
            {
                ++(*injectedYet);

                pLH.completeLog("packets in session #%d %s:%u Sj.hack %s (min %d max %d)", *injectedYet, 
                                inet_ntoa(*((struct in_addr *) &(origpkt.ip->daddr))), ntohs(origpkt.tcp->dest),
                                ret ? "TRUE" : "FALSE", MIN_INJECTED_PKTS, MAX_INJECTED_PKTS);
            }
        }

        return ret;
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->randomizeID();

        pkt->tcp->rst = 1;
        pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) + (65535 * 5) + (random() % 65535) );
        pkt->tcp->window = htons((uint16_t) (-1));

        /* tcp->ack and tcp->ack_seq is kept untouched */
        pkt->tcp->psh = 0;

        pkt->tcppayloadResize(0);

        pkt->source = PLUGIN;
        pkt->position = ANY_POSITION;
        pkt->wtf = INNOCENT;

        /* useless, INNOCENT is never downgraded in last_pkt_fix, but safe */
        pkt->choosableScramble = SCRAMBLE_INNOCENT;

        /* this packet will became dangerous if hacked again...
           is an INNOCENT RST based on the seq... */
        pkt->chainflag = FINALHACK;

        pktVector.push_back(pkt);
    }
};

extern "C" Plugin* createPluginObj()
{
    return new valid_rst_fake_seq();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
