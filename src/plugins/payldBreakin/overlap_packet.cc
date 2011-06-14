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
#define MIN_PACKET_OVERTRY 200

#define SEQINFO 1

private:

    pluginLogHandler pLH;
    /*
     * how does it works ? 
     * suppose to have a packet long 200 byte with sequcence X
     *
     * this plugin will send:
     * seq X len 60
     * seq (X + 40) len 80 (and cache, X + 120 value)
     * seq X len 200
     * seq (X + 120) len 80 (and cache ? boh!)
     *
     * when the incoming check found an ack_seq of X + 60, drop it.
     */
    PluginCache OVRLAPcache;

    Packet * create_segment(const Packet &pkt, uint32_t seqOff, uint16_t newTcplen, bool cache, bool psh, bool ackkeep)
    {
        Packet * ret = new Packet(pkt);

        ret->randomizeID();
        ret->tcp->seq = htonl( ntohl(ret->tcp->seq) + seqOff );

        pLH.completeLog("creation of %d: seqOff %d (%u) new len %d + cache (%s) push (%s) ack (%s)",
                        ret->SjPacketId, seqOff, ntohl(ret->tcp->seq), newTcplen,
                        cache ? "YES" : "NO", psh ? "YES" : "NO", ackkeep ? "YES" : "NO");

        if(newTcplen != ret->tcppayloadlen)
        {
            ret->tcppayloadResize(newTcplen);
            memset_random(ret->tcppayload, newTcplen);
        }

        if(!psh)
        {
            ret->tcp->psh = 0;
        }

        /* this is checked in every generated packet, to avoid ack duplications */
        if(!ackkeep)
        {
            ret->tcp->ack = 0;
            ret->tcp->ack_seq = 0;
        }

        ret->source = PLUGIN;
        ret->wtf = INNOCENT;
        ret->choosableScramble = SCRAMBLE_INNOCENT;
        upgradeChainFlag(ret);

        if(cache)
        {
            uint32_t expectedAck = htonl(ntohl(ret->tcp->seq) + newTcplen);

            pLH.completeLog("+ expected Ack %u added to the cache (orig seq %u)", ntohl(expectedAck), ntohl(ret->tcp->seq) );
            
            OVRLAPcache.add(*ret, (const unsigned char *)&expectedAck, sizeof(expectedAck));
        }
        else
        {
            uint32_t dbg = (ntohl(ret->tcp->seq) + newTcplen);
            pLH.completeLog("? debug: orig seq %u ack_seq %u pushed len %d (w/out cache)", ntohl(ret->tcp->seq), (dbg), newTcplen );
        }

        return ret;
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

    virtual void mangleIncoming(Packet &inpkt)
    {
        if( ntohs(inpkt.tcp->source) != 80 )
            return;

        cacheRecord *acked = OVRLAPcache.check(&ackedseqMatch, inpkt);

        if (acked != NULL)
        {
            pLH.completeLog("! ack-seq match: (%u) packet removed", ntohl(inpkt.tcp->ack_seq));

            removeOrigPkt = true;
        }
        else
            pLH.completeLog("# incoming ack_seq (%u) not removed", ntohl(inpkt.tcp->ack_seq));
    }

    /* the only acceptable Scramble is INNOCENT, because the hack is based on
     * overlap the fragment of the same packet */
    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag != HACKUNASSIGNED)
            return false;

        if (origpkt.chainflag == FINALHACK || origpkt.proto != TCP || origpkt.fragment == true)
            return false;
/*
        pLH.completeLog("verifing condition for ip.id %d Sj#%u (dport %u) datalen %d total len %d seq %u",
                        ntohs(origpkt.ip->id), origpkt.SjPacketId, ntohs(origpkt.tcp->dest), 
                        origpkt.tcppayloadlen, origpkt.pbuf.size(), ntohl(origpkt.tcp->seq) );
*/
        /* preliminar condition, TCP and fragment already checked */
        bool ret = (!origpkt.tcp->syn && !origpkt.tcp->rst && 
                     origpkt.tcppayload != NULL && origpkt.tcppayloadlen > MIN_PACKET_OVERTRY);

        if (!ret)
            return false;

        return ret;
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        Packet * const pkt1 = create_segment(origpkt, 0, 60, false, false, true);
        pkt1->position = ANTICIPATION;
        pktVector.push_back(pkt1);

        Packet * const pkt2 = create_segment(origpkt, 40, 80, true, false, false);
        pkt2->position = ANTICIPATION;
        pktVector.push_back(pkt2);

        Packet * const pkt3 = create_segment(origpkt, 0, origpkt.tcppayloadlen, false, true, false);
        pkt3->position = ANTICIPATION;
        pktVector.push_back(pkt3);

        Packet * const pkt4 = create_segment(origpkt, 120, 80, false, false, false);
        pkt4->position = POSTICIPATION;
        pktVector.push_back(pkt4);

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


