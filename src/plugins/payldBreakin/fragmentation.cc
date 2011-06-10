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

    /*  RFC 791 states:
     * "Every internet module must be able to forward a datagram of 68
     *  octets without further fragmentation.  This is because an internet
     *  header may be up to 60 octets, and the minimum fragment is 8 octets."
     */
#define MIN_EXIST_PAYLOAD 8 

    /*
     * An IP Fragment Too Small exploit is when any fragment other than the final fragment 
     * is less than 400 bytes, indicating that the fragment is likely intentionally crafted. 
     * Small fragments may be used in denial of service attacks or in an attempt to bypass 
     * security measures or detection. -- we don't want trigger this alarm!
     * https://secure.wikimedia.org/wikipedia/en/wiki/IP_fragmentation_attacks
     */
#define MIN_USABLE_MTU      576
#define MIN_HANDLING_LEN  (MIN_USABLE_MTU + MIN_EXIST_PAYLOAD)

/* space kept beside iphdr for ip options injection: the payload remaning = 68 * 8 */
#define MIN_OPTION_RESERVED 12

private:

    pluginLogHandler pLH;

    /* the cache is used for keep track of the packet loss impact over a fragmented session */
    PluginCache FRAGcache;

public:

    fragmentation() :
    Plugin(PLUGIN_NAME, AGG_ALWAYS),
    pLH(PLUGIN_NAME, PKT_LOG)
    {
    }

    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        if (!(ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble)))
        {
            LOG_ALL("%s plugin supports only INNOCENT scramble type", PLUGIN_NAME);
            return false;
        }

        pLH.completeLog("Initialization of fragmentation plugin (in the future, will be a scramble)");
        supportedScrambles = SCRAMBLE_INNOCENT;

        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        bool ret;

        if (origpkt.chainflag == FINALHACK || origpkt.proto != TCP || origpkt.fragment == true)
            return false;

        if (!(availableScrambles & supportedScrambles))
        {
            origpkt.SELFLOG("no scramble avalable for %s", PLUGIN_NAME);
            return false;
        }

        /* we didn't check "origpkt.ip->frag_off & htons(IP_DF)" because want to _force_ frag */
        ret = (origpkt.ippayloadlen >= MIN_HANDLING_LEN);

        pLH.completeLog("verified condition for ip.id %d Sj#%u ip payld %d tcp payld %d total len %d: %s",
                        ntohs(origpkt.ip->id), origpkt.SjPacketId, origpkt.ippayloadlen,
                        origpkt.tcppayloadlen, origpkt.pbuf.size(), ret ? "ACCEPT" : "REJECT");

        return ret;
    }

    Packet * create_fragment(const Packet &origpkt, uint16_t since, uint16_t len)
    {
        Packet * ret = new Packet(origpkt, since, len, MIN_USABLE_MTU);

        ret->source = PLUGIN;

        /* the orig packet is removed, the position has no particular importance for the hack
         * anyway ANTICIPATION keep packets trasmission ordered. */
        ret->position = ANTICIPATION;

        /* we keep the origpkt.wtf to permit this hack to segment both good and evil pkts */
        ret->wtf = origpkt.wtf;

        /* will be re-hacked, of couse, also if not all plugins supports frag */
        upgradeChainFlag(ret);

        return ret;
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        uint16_t start = 0;
        uint16_t tobesend = origpkt.ippayloadlen;
        Packet * fragPkt;

        /* fragDataLen is 544 byte of ip payload */
        uint16_t fragDataLen = (MIN_USABLE_MTU - (sizeof(struct iphdr) + MIN_OPTION_RESERVED) );

        /* ** ** **
         * choose if generate TWO or THREE fragments:
         *
         * REMIND/TODO/WISHLIST: declaring our MTU to $ALOT, sniffjoke will choose internally if use 
         * TCP segmentation or IP fragmentation, where is possibile. 
         * ** ** **/
        int32_t not_last_pkts;

        /* packets with (tcp + data) > 1088 are splitted in three, one "last pkts" is always present */
        if (( origpkt.ippayloadlen - (fragDataLen * 2) )  > 0 )
            not_last_pkts = 2;
        else
            not_last_pkts = 1;

        /* create the 1st (and 2nd ?) fragments */
        do 
        {
            fragPkt = create_fragment(origpkt, start, fragDataLen);
            fragPkt->choosableScramble = (availableScrambles & supportedScrambles);

            fragPkt->ip->frag_off = htons( (start >> 3) & IP_OFFMASK);

            pLH.completeLog("%d (Sj#%u) totl %d start %d fragl %u (tobesnd %d) frag_off %u origseq %u origippld %u", 
                            not_last_pkts, fragPkt->SjPacketId, fragPkt->pbuf.size(), start, fragDataLen, tobesend,
                            ntohs(fragPkt->ip->frag_off), ntohl(origpkt.tcp->seq), origpkt.ippayloadlen );

            fragPkt->ip->frag_off |= htons(IP_MF);

            pktVector.push_back(fragPkt);

            start += fragDataLen;
            tobesend -= fragDataLen;

        } while(--not_last_pkts);

        /* create the last fragment */
        fragPkt = create_fragment(origpkt, start, tobesend);
        fragPkt->choosableScramble = (availableScrambles & supportedScrambles);

        fragPkt->ip->frag_off = htons( (start >> 3) & IP_OFFMASK);

        pktVector.push_back(fragPkt);

        pLH.completeLog("final fragment (Sj#%u) size %d start %d (frag_off %u) orig seq %u", 
                        fragPkt->SjPacketId, fragPkt->pbuf.size(), start,
                        ntohs(fragPkt->ip->frag_off), ntohl(origpkt.tcp->seq) );

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
