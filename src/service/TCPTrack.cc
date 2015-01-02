/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *
 *   Copyright (C) 2008,2009,2010,2011
 *                 vecna <vecna@delirandom.net>
 *                 evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include "TCPTrack.h"

#include "UserConf.h"
#include "SessionTrack.h"
#include "TTLFocus.h"
#include "PluginPool.h"

extern auto_ptr<UserConf> userconf;
extern auto_ptr<SessionTrackMap> sessiontrack_map;
extern auto_ptr<TTLFocusMap> ttlfocus_map;
extern auto_ptr<PluginPool> plugin_pool;

TCPTrack::TCPTrack()
{
    LOG_DEBUG("");

    mangled_proto_mask = ICMP;

    if (!userconf->runcfg.no_tcp)
        mangled_proto_mask |= TCP;

    if (!userconf->runcfg.no_udp)
        mangled_proto_mask |= UDP;
}

TCPTrack::~TCPTrack(void)
{
    LOG_DEBUG("");
}

uint32_t TCPTrack::derivePercentage(uint32_t packet_number, uint16_t frequencyValue)
{

    if (userconf->runcfg.onlyplugin[0])
        frequencyValue = AGG_ALWAYS;

    uint32_t freqret = 0;

    if (frequencyValue & AGG_VERYRARE)
    {
        freqret += 5;
    }
    if (frequencyValue & AGG_RARE)
    {
        freqret += 15;
    }
    if (frequencyValue & AGG_COMMON)
    {
        freqret += 40;
    }
    if (frequencyValue & AGG_HEAVY)
    {
        freqret += 75;
    }
    if (frequencyValue & AGG_ALWAYS)
    {
        freqret += 100;
    }
    if (frequencyValue & AGG_PACKETS10PEEK)
    {
        if (!(++packet_number % 10) || !(--packet_number % 10) || !(--packet_number % 10))
            freqret += 80;
        else
            freqret += 2;
    }
    if (frequencyValue & AGG_PACKETS30PEEK)
    {
        if (!(++packet_number % 30) || !(--packet_number % 30) || !(--packet_number % 30))
            freqret += 90;
        else
            freqret += 2;
    }
    if (frequencyValue & AGG_TIMEBASED5S)
    {
        if (!((uint8_t) sj_clock % 5))
            freqret += 90;
        else
            freqret += 2;
    }
    if (frequencyValue & AGG_TIMEBASED20S)
    {
        if (!((uint8_t) sj_clock % 20))
            freqret += 90;
        else
            freqret += 2;
    }
    if (frequencyValue & AGG_STARTPEEK)
    {
        if (packet_number < 20)
            freqret += 65;
        else if (packet_number < 40)
            freqret += 20;
        else
            freqret += 2;
    }
    if (frequencyValue & AGG_LONGPEEK)
    {
        if (packet_number < 60)
            freqret += 55;
        else if (packet_number < 120)
            freqret += 20;
        else
            freqret += 2;
    }
    if (frequencyValue & AGG_HANDSHAKE)
    {
        if (packet_number < 4)
            freqret += 100;
        else
            freqret = 0;
    }
    if (frequencyValue & AGG_NONE)
        freqret = 0;

    return freqret;
}

/*
 *  this function is used from the injectHack() routine to decretee
 *  the possibility for an hack to happen.
 *  returns true if it's possibile to forge the hack.
 *  the calculation involves:
 *   - the session packet count; a variable inside the equation (some hacks are
 *     configured to act in peek time or packets number relationship)
 *   - the frequency selector provided from the hack developer; used when the
 *     port-aggressivity.conf file don't provide a specific configuration.
 *   - the port configuration settings: derived from 'port-aggressivity.conf'
 */
bool TCPTrack::percentage(uint32_t packet_number, uint16_t hackFrequency, uint16_t userFrequency)
{
    uint32_t aggressivity_percentage = 0;

    /*
     * as first is checked hackFrequency, because it could be AGG_ALWAYS
     * and this means that we are in testing mode with --only-olugin option
     */
    if (hackFrequency & AGG_ALWAYS)
        return true;

    aggressivity_percentage = derivePercentage(packet_number, userFrequency);

    return ( ((uint32_t) random() % 100) < aggressivity_percentage);
}

uint16_t TCPTrack::getUserFrequency(const Packet &pkt)
{
    /* MUST be called on TCP/UDP packet only */

    if (pkt.proto == TCP)
        return userconf->runcfg.portconf[ntohs(pkt.tcp->dest)];

    /* else, no other proto other than UDP will reach here.
     *
     * the UDP traffic is for the most a data-apply hacks, because no flag gaming
     * nor sequence hack exists. when a service is request to be ALWAYS hacked, we
     * accept this choose in UDP too. otherwise, is better use a costant noise
     * using AGG_COMMON */

    if (userconf->runcfg.portconf[ntohs(pkt.udp->dest)] == AGG_ALWAYS)
        return AGG_ALWAYS;

    return AGG_COMMON;
}

uint8_t TCPTrack::discernAvailScramble(const Packet &pkt)
{
    /*
     * TODO - when we will integrate passive os fingerprint and
     * we will do a a clever study about different OS answers about
     * IP option, for every OS we will have or not the related support
     */
    uint8_t retval = SCRAMBLE_INNOCENT | SCRAMBLE_CHECKSUM | SCRAMBLE_MALFORMED;

    TTLFocus &ttlfocus = ttlfocus_map->get(pkt);
    if (ttlfocus.status == TTL_KNOWN)
        retval |= SCRAMBLE_TTL;

    return retval;
}

/*
 * this function is responsable of the ttl bruteforce stage used
 * to detect the hop distance between us and the remote peer.
 *
 * SniffJoke uses the first seen session packet as a starting point
 * for this stage.
 *
 * packets generated are a copy of the original (first seen) packet
 * with some little modifications to:
 *  - ip->id ....... is used a univoke marker, useful for detect which packet
 *                   is returned as part of an ICMP time exceeded
 *  - ip->ttl ...... is under incrmeental probe, like a traceroute
 *  - tcp->source .. is required to modify it because will bring problem to 
 *                   the real connection, if kept the same
 *  - tcp->seq ..... same reason of ip->id, but used for check the SYN+ACK
 *                   having this univoke random seq as +1 in the ack_seq
 *
 */
void TCPTrack::injectTTLProbe(TTLFocus &ttlfocus)
{
    Packet *injpkt;

    switch (ttlfocus.status)
    {
    case TTL_UNKNOWN:
        ttlfocus.status = TTL_BRUTEFORCE;
        /* do not break, continue inside TTL_BRUTEFORCE */
    case TTL_BRUTEFORCE:
        if (ttlfocus.sent_probe == userconf->runcfg.max_ttl_probe)
        {
            if (!ttlfocus.probe_timeout)
            {
                ttlfocus.probe_timeout = sj_clock + 2;
            }
            else if (ttlfocus.probe_timeout < sj_clock)
            {
                ttlfocus.status = TTL_UNKNOWN;
                ttlfocus.sent_probe = 0;
                ttlfocus.received_probe = 0;
                ttlfocus.ttl_estimate = 0xFF;
                ttlfocus.ttl_synack = 0;
                ttlfocus.next_probe_time = sj_clock + TTLPROBE_RETRY_ON_UNKNOWN;
            }
            break;
        }
        else
        {
            ++ttlfocus.sent_probe;
            injpkt = new Packet(ttlfocus.probe_dummy, sizeof (ttlfocus.probe_dummy));
            injpkt->source = TRACEROUTE;
            injpkt->wtf = INNOCENT;
            injpkt->ip->id = htons((ttlfocus.rand_key % 64) + ttlfocus.sent_probe);
            injpkt->ip->ttl = ttlfocus.sent_probe;
            injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttlfocus.sent_probe);

            injpkt->fixIPTCPSum();
            p_queue.insert(*injpkt, SEND);

            /* the next ttl probe schedule is forced in the next cycle */
            ttlfocus.next_probe_time = sj_clock;

            injpkt->SELFLOG("TTL_BRUTEFORCE #sent|%u ttl_estimate|%u",
                            ttlfocus.sent_probe, ttlfocus.ttl_estimate);
            break;
        }
    case TTL_KNOWN:
        /* TODO: Handle the KNOWN status; find a way to detect network topology changes. */
        break;
    }
}

/*
 * verifies the need of ttl probes for active destinations
 */
void TCPTrack::execTTLBruteforces(void)
{
    for (TTLFocusMap::iterator it = ttlfocus_map->begin(); it != ttlfocus_map->end(); ++it)
    {
        TTLFocus &ttlfocus = *((*it).second);
        if ((ttlfocus.status != TTL_KNOWN) /* 1) the ttl is BRUTEFORCE or UNKNOWN */
                && (ttlfocus.access_timestamp > (sj_clock - 30)) /* 2) the destination it's used in the last 30 seconds */
                && (ttlfocus.next_probe_time <= sj_clock)) /* 3) the next probe time it's passed */
        {
            injectTTLProbe(*(*it).second);
        }
    }
}

/*
 *
 * extracts TTL information from an incoming packet
 *
 * the function returns TRUE if the packet has been identified as an answer to
 * the ttlbruteforce session and has to be removed.
 *
 * in this function we call the find() method of std::map because
 * we want to test the ttl existence and NEVER NEVER NEVER create a new one
 * to not permit an external packet to force us to activate a ttlbrouteforce session.
 *
 * the function returns TRUE if a plugins has requested the removal of the packet.
 */
bool TCPTrack::extractTTLinfo(const Packet &incompkt)
{
    TTLFocusMap::iterator it;
    TTLFocus *ttlfocus;

    /* if the pkt is an ICMP TIME_EXCEEDED should contain informations useful for
     * discern HOP distance from a remote host.  */
    if (incompkt.proto == ICMP && incompkt.icmp->type == ICMP_TIME_EXCEEDED)
    {
        const struct iphdr * const badiph = (struct iphdr *) ((unsigned char *) incompkt.icmp + sizeof (struct icmphdr));
        const struct tcphdr * const badtcph = (struct tcphdr *) ((unsigned char *) badiph + (badiph->ihl * 4));

        /* we are looking only for our TCP expired pkts */
        if (badiph->protocol != IPPROTO_TCP)
            return false;

        /* if is not tracked, the user is making a tcptraceroute */
        if ((it = ttlfocus_map->find(badiph->daddr)) == ttlfocus_map->end())
            return false;

        ttlfocus = it->second;

        const uint8_t expired_ttl = ntohs(badiph->id) - (ttlfocus->rand_key % 64);
        const uint8_t exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

        if (expired_ttl == exp_double_check)
        {
            if (ttlfocus->status == TTL_BRUTEFORCE)
            {
                incompkt.SELFLOG("incoming ICMP EXPIRED puppet|%d expired|%d",
                                 ttlfocus->puppet_port, expired_ttl);

                ttlfocus->received_probe++;

                /*
                 * every time a time exceded it's received. if the MAXTTLPROBE has
                 * been reached (ttlfocus->probe_timeout != 0), the probe_timeout
                 * it's resetted.
                 */
                if (ttlfocus->probe_timeout)
                    ttlfocus->probe_timeout = sj_clock + 2;

                if (expired_ttl >= ttlfocus->ttl_estimate)
                {
                    /*
                     * if we are changing our estimation due to an expired
                     * we have to set status = TTL_UNKNOWN
                     * this is important to permit recalibration.
                     */
                    ttlfocus->status = TTL_UNKNOWN;
                    ttlfocus->ttl_estimate = expired_ttl + 1;
                }
            }

            /* the expired icmp scattered due to our ttl probes,
             * so we can trasparently remove it. */
            return true;
        }
    }

    /* a tracked TCP packet contains important TTL informations */
    if ((incompkt.proto != TCP || (it = ttlfocus_map->find(incompkt.ip->saddr)) == ttlfocus_map->end()))
        return false;

    ttlfocus = it->second;

    /* a SYN ACK will be the answer at our probe! */
    if (incompkt.tcp->syn && incompkt.tcp->ack && (incompkt.tcp->dest == htons(ttlfocus->puppet_port)))
    {
        if (ttlfocus->status != TTL_BRUTEFORCE)
        {
            incompkt.SELFLOG("incoming SYN/ACK weird: puppet port in a session outside ttl bruteforce");
            return false;
        }
        /*
         * this section analyze the TCP syn+ack:
         * in the ttlbruteforce stage a syn + ack will be bringer of a ttl information.
         * if the received packet matches the puppet port used for the current
         * ttlbruteforce session we can discern the ttl as:
         *
         *     unsigned char discern_ttl =  ntohl(pkt.tcp->ack_seq) - ttlfocus->rand_key - 1;
         *
         * this because the sequence number used in the TTL bruteforce has hardcoded the
         * number of the TTL.
         */
        uint8_t discern_ttl = ntohl(incompkt.tcp->ack_seq) - ttlfocus->rand_key - 1;

        ++ttlfocus->received_probe;

        if (discern_ttl < ttlfocus->ttl_estimate)
        {
            ttlfocus->ttl_estimate = discern_ttl;
            ttlfocus->ttl_synack = incompkt.ip->ttl;
        }

        ttlfocus->status = TTL_KNOWN;

        incompkt.SELFLOG("incoming SYN/ACK puppet|%d ttl_estimate|%d ttl_synack|%d",
                         ttlfocus->puppet_port, ttlfocus->ttl_estimate, ttlfocus->ttl_synack);
        ttlfocus->SELFLOG("incoming SYN/ACK puppet|%d ttl_estimate|%d ttl_synack|%d",
                          ttlfocus->puppet_port, ttlfocus->ttl_estimate, ttlfocus->ttl_synack);

        return true;
    }
    else
    {
        if (ttlfocus->status == TTL_KNOWN && ttlfocus->ttl_synack != incompkt.ip->ttl)
        {

            /* probably a topology change has happened - we need a solution wtf!!  */
            incompkt.SELFLOG("probable net topology change! ttl_estimate|%u synack ttl|%u received_ttl|%u]",
                             ttlfocus->ttl_estimate, ttlfocus->ttl_synack, incompkt.ip->ttl);
        }
        return false;
    }
}

/*
 * notifies all plugins at the arrival of an incoming packet;
 * if a plugin does not need this notification simply can return immediatly.
 *
 * the function returns TRUE if a plugins has requested the removal of the packet.
 */
#define ENABLE_INCOMING_DEBUG
/* at the moment, only few plugins mangle the input packet, enable this debug when needed */
#undef ENABLE_INCOMING_DEBUG

bool TCPTrack::notifyIncoming(Packet &origpkt)
{
    bool removeOrig = false;

#ifdef ENABLE_INCOMING_DEBUG
    origpkt.SELFLOG("orig pkt: before incoming mangle");
#endif

    for (vector<PluginTrack*>::iterator it = plugin_pool->pool.begin(); it != plugin_pool->pool.end(); ++it)
    {
        PluginTrack *pt = *it;

        pt->selfObj->mangleIncoming(origpkt);

        /* it will be rare for a hack mangleIncoming to generate one or more packet, anyway we keep this possibility possible */
        for (vector<Packet*>::iterator hack_it = pt->selfObj->pktVector.begin(); hack_it < pt->selfObj->pktVector.end(); ++hack_it)
        {
            Packet &injpkt = **hack_it;

            if (!injpkt.selfIntegrityCheck(pt->selfObj->pluginName))
            {
                LOG_ALL("%s: invalid pkt generated", pt->selfObj->pluginName);
                injpkt.SELFLOG("%s: bad integrity", pt->selfObj->pluginName);

                /* if you are running with --debug 6, I suppose you are the developing the plugins */
                if (userconf->runcfg.debug_level == PACKET_LEVEL)
                    RUNTIME_EXCEPTION("%s: invalid pkt generated", pt->selfObj->pluginName);

                /* otherwise, the error was reported and sniffjoke continue to work */
                delete &injpkt;
                continue;
            }

            /* lastPktFix is called because the checksum will not be correct */
            if (!lastPktFix(injpkt))
                continue;

#ifdef ENABLE_INCOMING_DEBUG
            injpkt.SELFLOG("%s: generated packet, the original (i%u) will be %s",
                           pt->selfObj->pluginName, origpkt.SjPacketId,
                           pt->selfObj->removeOrigPkt ? "REMOVED" : "KEPT");
#endif

            /* injpkt.position is ignored in this section because mangleIncoming
             * is called on the YOUNG queue.
             * ATM we inject in the SEND queue so every packet generated
             * in mangleIncoming is equal to be ANTICIPATION */
            p_queue.insert(injpkt, SEND);
        }

        if (pt->selfObj->removeOrigPkt == true)
            removeOrig = true;

        pt->selfObj->reset();
    }

#ifdef ENABLE_INCOMING_DEBUG
    origpkt.SELFLOG("orig pkt: after incoming mangle");
#endif

    return removeOrig;
}

/*
 * injectHack is one of the core function in sniffjoke and handles the hack injection.
 * the function returns TRUE if a plugins has requested the removal of the packet.
 */
bool TCPTrack::injectHack(Packet &origpkt)
{
    bool removeOrig = false;

    SessionTrack &sessiontrack = sessiontrack_map->get(origpkt);

    vector<PluginTrack *> applicable_hacks;

    /*
     * Not all time we have a scramble available, we tell to the plugin which of
     * them are usable, and the packets is returned. the most of the time, all of
     * three scramble are available, and the plugins will use pktRandomDamage()
     * private method.
     */
    uint8_t availableScrambles = discernAvailScramble(origpkt);

    char availableScramblesStr[LARGEBUF] = {0};
    snprintfScramblesList(availableScramblesStr, sizeof (availableScramblesStr), availableScrambles);

    /* SELECT APPLICABLE HACKS, the selection are base on:
     * 1) the plugin/hacks detect if the condition exists (eg: the hack wants a SYN and the packet is a RST+ACK)
     * 2) compute the percentage: mixing the hack-choosed and the user-choose  */
    for (vector<PluginTrack*>::iterator it = plugin_pool->pool.begin(); it != plugin_pool->pool.end(); ++it)
    {

        PluginTrack *pt = *it;

        /*
         * this represents a preliminar check common to all hacks.
         * more specific ones related to the origpkt will be checked in
         * the condition function implemented by a specific hack.
         */
        if ((!(availableScrambles & pt->selfObj->supportedScrambles)) && (userconf->runcfg.debug_level == PACKET_LEVEL))
        {
            char pluginavaileScrambStr[LARGEBUF] = {0};

            snprintfScramblesList(pluginavaileScrambStr, sizeof (pluginavaileScrambStr), pt->selfObj->supportedScrambles);

            origpkt.SELFLOG("%s: no scramble matching between system avail [%s] and plugins scramble [%s]",
                            pt->selfObj->pluginName, availableScramblesStr, pluginavaileScrambStr);
            continue;
        }

        bool applicable = true;

        applicable &= pt->selfObj->condition(origpkt, availableScrambles);
        applicable &= percentage(sessiontrack.packet_number, pt->selfObj->pluginFrequency, getUserFrequency(origpkt));

        if (applicable)
            applicable_hacks.push_back(pt);
    }

    if (!applicable_hacks.size() && (userconf->runcfg.debug_level == PACKET_LEVEL))
        origpkt.SELFLOG("NONE hack plugin has been passed the selection!");

    /* -- RANDOMIZE HACKS APPLICATION */
    random_shuffle(applicable_hacks.begin(), applicable_hacks.end());

    /* -- FINALLY, HACK THE CHOOSEN PACKET(S) */
    for (vector<PluginTrack *>::iterator it = applicable_hacks.begin(); it != applicable_hacks.end(); ++it)
    {

        PluginTrack *pt = *it;

        origpkt.SELFLOG("from %d avail plugins, %d has been selected: applying plugin [%s]", 
                        plugin_pool->pool.size(), applicable_hacks.size(), pt->selfObj->pluginName);

        pt->selfObj->apply(origpkt, availableScrambles);

        for (vector<Packet*>::iterator hack_it = pt->selfObj->pktVector.begin(); hack_it < pt->selfObj->pktVector.end(); ++hack_it)
        {
            Packet &injpkt = **hack_it;
            /*
             * we trust in the external developer, but it's required a
             * simple safety check by sniffjoke :)
             */
            if (!injpkt.selfIntegrityCheck(pt->selfObj->pluginName))
            {
                injpkt.SELFLOG("%s: invalid pkt generated: bad integrity", pt->selfObj->pluginName);

                /* if you are running with --debug 6, I suppose you are the developing the plugins */
                if (userconf->runcfg.debug_level == PACKET_LEVEL)
                    RUNTIME_EXCEPTION("%s invalid pkt generated: bad integrity", pt->selfObj->pluginName);

                /* otherwise, the error was reported and sniffjoke continue to work */
                delete &injpkt;
                continue;
            }

            if (!lastPktFix(injpkt))
            {
                continue;
            }

            /* setting for debug pourpose: sniffjokectl info will show this value */
            sessiontrack.injected_pktnumber++;

            packet_filter.add(injpkt);

            injpkt.SELFLOG("NEW packet from [%s], the original (i%u) will be %s",
                           pt->selfObj->pluginName, origpkt.SjPacketId,
                           pt->selfObj->removeOrigPkt ? "REMOVED" : "KEPT");

            switch (injpkt.position)
            {
            case ANTICIPATION:
                p_queue.insertBefore(injpkt, origpkt);
                break;
            case POSTICIPATION:
                p_queue.insertAfter(injpkt, origpkt);
                break;
            case ANY_POSITION:
                if (random() % 2)
                    p_queue.insertBefore(injpkt, origpkt);
                else
                    p_queue.insertAfter(injpkt, origpkt);
                break;
            case POSITIONUNASSIGNED:
                RUNTIME_EXCEPTION("FATAL CODE [D4L1]: please send a notification to the developers");
            }
        }

        if (pt->selfObj->removeOrigPkt == true)
            removeOrig = true;

        pt->selfObj->reset();
    }

    return removeOrig;
}

/*
 * lastPktFix is the last modification applied to outgoing packets.
 * modification involve only TCP/UDP packets coming from TUNNEL
 * and hacks injected in the queue to goes on the eth/wifi.
 *
 * p.s. if you are reading this piece of code to fix your sniffer:
 *   we SHALL BE YOUR NIGHTMARE.
 *   we SHALL BE YOUR NIGHTMARE.
 *   we SHALL BE YOUR NIGHTMARE, LOSE ANY HOPE, we HAD THE RANDOMNESS IN OUR SIDE.
 *
 *
 *  PRESCRIPTION: will EXPIRE BEFORE REACHING destination (due to ttl modification)
 *                could be: ONLY EVIL PACKETS
 *   GUILTY:      will BE DISCARDED by destination (due to some error introduction)
 *                at the moment the only error applied is the invalidation tcp checksum
 *                could be: ONLY EVIL PACKETS
 *   MALFORMED:   will BE DISCARDED by destination due to misuse of ip options
 *                could be: ONLY EVIL PACKETS
 *   INNOCENT:    will BE ACCEPTED, so, INNOCENT but EVIL cause the same treatment of a
 *                GOOD packet.
 *
 * hacks application follows this order: PRESCRIPTION, MALFORMED, GUILTY.
 * a non applicable hack it's degraded to the next;
 * at worst GUILTY it's always applied.
 */
bool TCPTrack::lastPktFix(Packet &pkt)
{
    TTLFocus &ttlfocus = ttlfocus_map->get(pkt);

    if (ttlfocus.status == TTL_KNOWN)
    {
        /* WHAT VALUE OF TTL GIVE TO THE PACKET ? */
        if (pkt.wtf == PRESCRIPTION)
        {
            pkt.ip->ttl = ttlfocus.ttl_estimate - (1 + (random() % 2)); /* [-1, -2], 2 values */
        }
        else
        {
            /* MISTIFICATION FOR WTF != PRESCRIPTION */
            /* apply mystification if PRESCRIPTION is globally enabled */
            if (ISSET_TTL(plugin_pool->enabledScrambles()))
                pkt.ip->ttl = ttlfocus.ttl_estimate + (random() % 4); /* [+0, +3], 4 values */
        }
    }
    else
    {
        if (pkt.wtf == PRESCRIPTION)
        {
            if (ISSET_MALFORMED(pkt.choosableScramble))
            {
                pkt.SELFLOG("failed to corrupt pkt using prescription: pkt downgraded to MALFORMED");
                pkt.wtf = MALFORMED;
            }
            else if (ISSET_CHECKSUM(pkt.choosableScramble))
            {
                pkt.SELFLOG("failed to corrupt pkt using prescription: pkt downgraded to GUILTY");
                pkt.wtf = GUILTY;
            }
            else
            {
                pkt.SELFLOG("failed to corrupt pkt using prescription: pkt dropped");
                goto drop_packet;
            }
        }

        if (pkt.wtf != PRESCRIPTION)
        {
            /* MISTIFICATION APPLY ON DOWNGRADE, RANDOMIZING A BIT THE ORIGINAL TTL VALUE */
            /* apply mystification if PRESCRIPTION is globally enabled */
            if (ISSET_TTL(plugin_pool->enabledScrambles()))
                pkt.ip->ttl += (random() % 20) - 10; /* [-10, +10 ], 20 mystification values */
        }
    }

    /*
     * APPLY MALFORMATION OF IP/TCP OPTIONS, for good and evil packets is possible
     *
     * if wtf == MALFORMED and the scramble is not possible, wtf it's degraded to GUILTY.
     *
     * dropping when GUILTY is not supported happen only in sniffjoke-autotest
     */
    if (pkt.wtf == MALFORMED)
    {
        bool malformed = false;

        /* testing at the moment: are the IP options more relaibalbe ? */
        if (true /* pkt.fragment == true || pkt.proto != TCP || malformed == false */)
        {
            try
            {
                HDRoptions IPInjector(IPOPTS_INJECTOR, pkt, ttlfocus);
                if (IPInjector.injectRandomOpts(/* corrupt ? */ true, /* strip previous options */ true))
                    malformed = true;
            }
            catch (exception &e)
            {
                LOG_ALL("strip & inject IP opts (target: corrupt) fail: %s", e.what());
            }
        }

        if (malformed == false /* pkt.fragment == false && ( pkt.proto == TCP || random_percent(80) ) */)
        {
            try
            {
                HDRoptions TCPInjector(TCPOPTS_INJECTOR, pkt, ttlfocus);
                if (TCPInjector.injectRandomOpts(/* corrupt ? */ true, /* strip previous options */ true))
                    malformed = true;
            }
            catch (exception &e)
            {
                LOG_ALL("strip & inject TCP opts (target: corrupt) fail: %s", e.what());
            }
        }

        if (!malformed)
        {
            if (ISSET_CHECKSUM(pkt.choosableScramble))
            {
                pkt.SELFLOG("failed to corrupt pkt using MALFORMED: pkt downgraded to GUILTY");
                pkt.wtf = GUILTY;
            }
            else
            {
                pkt.SELFLOG("failed to corrupt pkt using MALFORMED: pkt dropped");
                goto drop_packet;
            }
        }
    }

    if (pkt.wtf != MALFORMED)
    {
        /* MISTIFICATION OF THE PACKET NOT YET CORRUPTED BY IP/TCP OPTIONS */

        /* IP/TCP options scambling enabled globally (and/or for destination) */
        if (ISSET_MALFORMED(plugin_pool->enabledScrambles()))
        {
            bool optmysty = false;

            /* testing in MALFORMED, 66 in normal usage, autotest usage is 100% */
            if ( random_percent(66) )
            {
                try
                {
                    HDRoptions IPInjector(IPOPTS_INJECTOR, pkt, ttlfocus);
                    IPInjector.injectRandomOpts(/* corrupt ? */ false, /* strip previous options ? */ false);
                    optmysty = true;
                }
                catch (exception &e)
                {
                    LOG_DEBUG("apply mystification with IP hdr options not possible: %s", e.what());
                }
            }

            if (optmysty == false /* random_percent(66) && pkt.proto == TCP */)
            {
                try
                {
                    HDRoptions TCPInjector(TCPOPTS_INJECTOR, pkt, ttlfocus);
                    TCPInjector.injectRandomOpts(/* corrupt ? */ false, /* strip previous options ? */ false);
                    optmysty = true;
                }
                catch (exception &e)
                {
                    LOG_DEBUG("apply mystification with TCP hdr options not possible: %s", e.what());
                }
            }
        }
    }

    /* in this place there WAS the randomPayload filling for packet != INNOCENT,
     * this was not correct, because the plugins will supply a specific layer 5
     * payload, for this reason I've moved the function in the plugins */

    /* fixing the mangled packet */
    pkt.fixSum();

    /*
     * corrupted checksum application if required;
     * this is the last resort for hacks packets if neither
     * PRESCRIPTION nor MALFORMED are applicable.
     */
    if (pkt.wtf == GUILTY)
        pkt.corruptSum();

    return true;

drop_packet:
    pkt.SELFLOG("pkt dropped during fix");
    p_queue.drop(pkt);

    return false;
}

/*
 * here we analyze YOUNG queue
 *
 * we handle only:
 *
 *   NETWORK packets:
 *     - we analyze them searching ttl informations.
 *     - we handle the removal of the orig packet if identified as an answer to ttlbruteforce.
 *     - we notify all plugins of the arrival of the packet;
 *       the packets are passed to the plugin because they will need to check
 *       or modify some information in them, or eventually also remove them.
 *     - after this analysis will be sent localy, because the packet
 *       coming from the gateway mac address has been actually dropped by the firewall rules.
 *
 *   TUNNEL packets:
 *     - we analyze tcp/udp packets to see if can be moved into HACK queue or if they
 *       need to be hold in status KEEP waiting for some conditions.
 *       every packets from the tunnel will be associated to a session (and session counter updated)
 *       and to a ttlfocus (if the ttlfocus not exists a new ttlbruteforce session is started).
 *
 *   any other pkt->source does scatter a fatal exception.
 */
void TCPTrack::handleYoungPackets(void)
{
    Packet *pkt = NULL;

    for (p_queue.select(YOUNG); ((pkt = p_queue.get()) != NULL);)
    {
        switch (pkt->source)
        {
        case NETWORK:

            /*
             * every incoming packet, triggered or not by our TTLBRUTEFORCE routine
             * will have useful informations for TTL stats.
             */
            if (extractTTLinfo(*pkt))
            {
                pkt->SELFLOG("removal requested by extractTTLinfo");
                p_queue.drop(*pkt);
                continue;
            }

            if (packet_filter.match(*pkt))
            {
                pkt->SELFLOG("removal requested by PacketFilter");
                p_queue.drop(*pkt);
                continue;
            }

            /* here we notify each plugin of the arrival of a packet */
            if (notifyIncoming(*pkt))
            {
                pkt->SELFLOG("removal requested by notifyIncoming");
                p_queue.drop(*pkt);
                continue;
            }

            /* packets received from network does not need to be hacked */
            p_queue.insert(*pkt, SEND);
            break;

        case TUNNEL:

            /* SniffJoke ATM does apply to TCP/UDP traffic only */
            if (pkt->proto & (TCP | UDP))
            {
                ++(sessiontrack_map->get(*pkt).packet_number);

                /*
                 * ATM we can put TCP only in KEEP status because
                 * due to the actual ttl bruteforce implementation a
                 * pure UDP flaw could go in starvation.
                 */
                if (pkt->proto == TCP && ttlfocus_map->get(*pkt).status == TTL_BRUTEFORCE)
                {
                    p_queue.insert(*pkt, KEEP);
                }
                else
                {
                    p_queue.insert(*pkt, HACK);
                }
            }
            else
            {
                p_queue.insert(*pkt, SEND);
            }
            break;

        default:

            RUNTIME_EXCEPTION("FATAL CODE [CYN1C]: please send a notification to the developers (%u)", pkt->source);
        }
    }
}

/*
 * here we analyze KEEP queue
 *
 * we handle only:
 *
 *   TUNNEL packets:
 *     - we analyze tcp/udp packets to see if can marked sendable or if they
 *       need to be hold in status KEEP waiting for some conditions.
 *
 *   any other pkt->source does scatter a fatal exception.
 */
void TCPTrack::handleKeepPackets(void)
{
    Packet *pkt = NULL;
    for (p_queue.select(KEEP); ((pkt = p_queue.getSource(TUNNEL)) != NULL);)
    {
        if (ttlfocus_map->get(*pkt).status != TTL_BRUTEFORCE)
            p_queue.insert(*pkt, HACK);
    }
}

/*
 * here we analyze HACK queue
 *
 * we handle only:
 *
 *   TUNNEL packets:
 *     - we analyze every packet, we fix and insert them into the SEND queue.
 *     - for each packet we forge hacks
 *     - we handle the removal of the orig packet if a forged hack has requested it.
 *
 *   any other pkt->source does scatter a fatal exception.
 */
void TCPTrack::handleHackPackets(void)
{
    /* for every packet in HACK queue we insert some random hacks */

    Packet *pkt = NULL;
    for (p_queue.select(HACK); ((pkt = p_queue.getSource(TUNNEL)) != NULL);)
    {
        if (!lastPktFix(*pkt))
            RUNTIME_EXCEPTION("FATAL CODE [M4CH3T3]: please send a notification to the developers");

        if (injectHack(*pkt))
        {
            pkt->SELFLOG("removal requested by injectHack");
            p_queue.drop(*pkt);
        }
    }

    if (userconf->runcfg.chaining == true)
    {
        for (p_queue.select(HACK); ((pkt = p_queue.getSource(PLUGIN)) != NULL);)
        {
            if (pkt->chainflag == REHACKABLE)
            {
                pkt->SELFLOG("proposing the packet for the second round: chaining hack");

                /* only the second generation hack are used */
                if (injectHack(*pkt))
                {
                    pkt->SELFLOG("removal requested by injectHack in the second round");
                    p_queue.drop(*pkt);
                }
            }
        }
    }

    for (p_queue.select(HACK); ((pkt = p_queue.get()) != NULL);)
        p_queue.insert(*pkt, SEND);
}

/* the packet is added in the packet queue here to be analyzed in a second time */
void TCPTrack::writepacket(source_t source, const unsigned char *buff, int nbyte)
{
    try
    {
        Packet * const pkt = new Packet(buff, nbyte);
        pkt->source = source;
        pkt->wtf = INNOCENT;
        pkt->choosableScramble = INNOCENT; /* on innocent pkts this variable is meaningless */

        /* Sniffjoke does handle only TCP, UDP and ICMP */
        if (userconf->runcfg.active && (pkt->proto & mangled_proto_mask))
        {
            if (userconf->runcfg.use_blacklist)
            {
                if (userconf->runcfg.blacklist->isPresent(pkt->ip->daddr) ||
                        userconf->runcfg.blacklist->isPresent(pkt->ip->saddr))
                {
                    p_queue.insert(*pkt, SEND);
                    return;
                }
            }
            else if (userconf->runcfg.use_whitelist)
            {
                if (!userconf->runcfg.whitelist->isPresent(pkt->ip->daddr) &&
                        !userconf->runcfg.whitelist->isPresent(pkt->ip->saddr))
                {
                    p_queue.insert(*pkt, SEND);
                    return;
                }
            }

            p_queue.insert(*pkt, YOUNG);
            return;
        }

        p_queue.insert(*pkt, SEND);

    }
    catch (exception &e)
    {
        /* anomalous/malformed packets are flushed bypassing the queue */
        LOG_ALL("malformed orig pkt dropped: %s", e.what());
    }
}

/*
 * this functions returns a packet from the SEND queue given a specific source
 */
Packet * TCPTrack::readpacket(source_t destsource)
{
    uint8_t mask;
    if (destsource == NETWORK)
        mask = NETWORK;
    else
        mask = TUNNEL | PLUGIN | TRACEROUTE;

    Packet *pkt = NULL;
    for (p_queue.select(SEND); ((pkt = p_queue.get()) != NULL);)
    {
        if (pkt->source & mask)
        {
            p_queue.extract(*pkt);
            return pkt;
        }
    }

    return NULL;
}

void TCPTrack::analyzePacketQueue(void)
{
    /* if all queues are empy we have nothing to do */
    if (!p_queue.size())
        goto bypass_queue_analysis;

    handleYoungPackets();
    handleKeepPackets();
    handleHackPackets();

bypass_queue_analysis:

    /*
     * here we call sessiontrack_map and ttlfocus_map manage routines.
     * it's fundamental to do this here after HACK last_packet_HACK()
     * and before ttl probes injections.
     * In fact the two routine, in case that their respective memory threshold
     * limits are passed, will delete the oldest records.
     * This is completely safe because send packets are just HACKed and there
     * is no problem if we does not schedule a ttlprobe for a cycle;
     * KEEP packets will scatter a new ttlfocus at the next.
     */

    sessiontrack_map->manage();
    ttlfocus_map->manage();

    execTTLBruteforces();
}

