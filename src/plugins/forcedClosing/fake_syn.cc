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
 * a SYN packet, in a sniffer reassembly routine should mean the allocation/
 * opening of a new flow. if this syn packet collide with a previously 
 * allocated tuple, what happen ? SYN and SYN+ACK became injected, wishing to 
 * to trigger something in the sniffers. 
 * 
 * SOURCE: deduction
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Plugin.h"

class fake_syn : public Plugin
{
#define PLUGIN_NAME "Fake SYNs"
#define PKT_LOG "plugin.fake_close_syn.log"
#define MIN_INJECTED_PKTS   6
#define MAX_INJECTED_PKTS   18
#define INJECTED_SYNS       3

private:
    pluginLogHandler pLH;

    /* every hack in "forcedClosing" has the same rules reported in FIN or RST plugins */
    PluginCache SYNcache;

    /* this is used because every loaded instance has different random boundaries in seq */
    uint32_t boundary;

public:

    fake_syn() :
    Plugin(PLUGIN_NAME, AGG_RARE),
    pLH(PLUGIN_NAME, PKT_LOG)
    {
    };

    virtual bool init(const scrambleMask &configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        boundary = ((random() % 5000) * 2);

        if(configuredScramble.willCorrupt())
        {
            supportedScrambles = configuredScramble;
            return true;
        }
        else
        {
            LOG_ALL("Plugin %s will not be loaded. Require some scramble supporting the corruption!", PLUGIN_NAME);
            LOG_ALL("in the configuration line, the scramble [%s] are not enough. 'man sniffjoke-plugins.conf'",
                   configuredScramble.debug()
            );
            return false;
        }
    }

    virtual bool condition(const Packet &origpkt, scrambleMask &availableScrambles)
    {
        bool ret = true;

        /* every flags combinations will be accepted in this hack */
        if (origpkt.chainflag == FINALHACK || origpkt.proto != TCP || origpkt.fragment == true)
            return false;

        pLH.completeLog("verifing condition for ip.id %d Sj#%u (dport %u) datalen %d total len %d",
                        ntohs(origpkt.ip->id), origpkt.SjPacketId, ntohs(origpkt.tcp->dest),
                        origpkt.tcppayloadlen, origpkt.pbuf.size());

        /* corruption is required to be available, perhaps usually will fall in the checksum
         * choosing, but this check is necessary */
        if(!availableScrambles.willCorrupt())
        {
            pLH.completeLog("scramble available don't support the pkts corruption [%s]",
                            availableScrambles.debug());
            return false;
        }

        /* cache checking, using the methods provide in the section 'forcedClosing' of Plugin.cc */
        cacheRecord* matchRecord;

        if ((matchRecord = verifyIfCache(&(tupleMatch), &SYNcache, origpkt)) != NULL)
        {
            uint32_t *injectedYet = (uint32_t*)&(matchRecord->cached_data[0]);

            /* if is present, inverseProp, return true with decreasing probability up to MAX_INJ */
            ret = inverseProportionality(*injectedYet, MIN_INJECTED_PKTS, MAX_INJECTED_PKTS);

            if (ret)
            {
                (*injectedYet) += INJECTED_SYNS;

                pLH.completeLog("packets #%d in session %s:%u Sj.hack %s (min %d max %d)", *injectedYet,
                                inet_ntoa(*((struct in_addr *) &(origpkt.ip->daddr))), ntohs(origpkt.tcp->dest),
                                ret ? "TRUE" : "FALSE", MIN_INJECTED_PKTS, MAX_INJECTED_PKTS);
            }
        }

        return ret;
    }

    virtual void apply(const Packet &origpkt, scrambleMask &availableScrambles)
    {
        for (uint8_t pkts = 0; pkts < INJECTED_SYNS; pkts++)
        {
            Packet * const pkt = new Packet(origpkt);

            pkt->randomizeID();

            if (random_percent(50))
                pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) + 65535 + (random() % boundary));
            else
                pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) - 65535 - (random() % boundary));

            /* 20% we use is a SYN+ACK instead of a simple SYN */
            if (random_percent(20))
            {
                pkt->tcp->ack = 1;
                pkt->tcp->ack_seq = random();
            }
            else
            {
                pkt->tcp->ack = 0;
                pkt->tcp->ack_seq = 0;
                /* REMIND: tipical IP/TCP opt of SYN pkts will be added */
            }

            /* 20% had source and dest port reversed */
            if (random_percent(20))
            {
                uint16_t swap = pkt->tcp->source;
                pkt->tcp->source = pkt->tcp->dest;
                pkt->tcp->dest = swap;
            }

            pkt->source = PLUGIN;
            pkt->wtf = CORRUPTNEED;
            upgradeChainFlag(pkt);
            
            if (random_percent(50))
                pkt->position = ANTICIPATION;
            else
                pkt->position = POSTICIPATION;


            pktVector.push_back(pkt);
        }
    }

    virtual void mangleIncoming(Packet &inpkt)
    {
    }
};

extern "C" Plugin* createPluginObj()
{
    return new fake_syn();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete (fake_syn *) who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
