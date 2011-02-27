/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2008 vecna <vecna@delirandom.net>
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

#include "TCPTrack.h"

#include <algorithm>

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

TCPTrack::TCPTrack(const sj_config &runcfg, HackPool &hpp, SessionTrackMap &sessiontrack_map, TTLFocusMap &ttlfocus_map) :
runconfig(runcfg),
sessiontrack_map(sessiontrack_map),
ttlfocus_map(ttlfocus_map),
hack_pool(hpp)
{
    LOG_DEBUG("");
}

TCPTrack::~TCPTrack(void)
{
    LOG_DEBUG("");
}

uint32_t TCPTrack::derivePercentage(uint32_t packet_number, uint16_t frequencyValue)
{
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

/*
 * this function analyze outgoing packets.
 * returns:
 *   - true if the packet could be SEND;
 *   - false if the bruteforce stage is active.
 *     in this case, the packet is mark as KEEP
 */
bool TCPTrack::analyzeOutgoing(Packet &pkt)
{
    ++(sessiontrack_map.get(pkt).packet_number);

    /* reming: TTL_BRUTEGORCE is the default for every ttlfocus obj */
    if (ttlfocus_map.get(pkt).status == TTL_BRUTEFORCE)
    {
        p_queue.remove(pkt);
        p_queue.insert(pkt, KEEP);
        return false;
    }

    return true;
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
 *  - ip->id
 *  - ip->ttl
 *  - tcp->source
 *  - tcp->seq
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
        if (ttlfocus.sent_probe == MAX_TTLPROBE)
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
            injpkt = new Packet(ttlfocus.probe_dummy);
            injpkt->mark(TTLBFORCE, INNOCENT, GOOD);
            injpkt->ip->id = (ttlfocus.rand_key % 64) + ttlfocus.sent_probe;
            injpkt->ip->ttl = ttlfocus.sent_probe;
            injpkt->tcp->source = htons(ttlfocus.puppet_port);
            injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttlfocus.sent_probe);

            injpkt->fixIpTcpSum();
            p_queue.insert(*injpkt, SEND);

            /* the next ttl probe schedule is forced in the next cycle */
            ttlfocus.next_probe_time = sj_clock;

            injpkt->SELFLOG("TTL_BRUTEFORCE probe# %u [ttl_estimate %u]",
                            ttlfocus.sent_probe, ttlfocus.ttl_estimate);
            break;
        }
    case TTL_KNOWN:
        /* TODO: Handle the KNOWN status; find a way to detect network topology changes. */
        break;
    }
}

void TCPTrack::execTTLBruteforces()
{
    /*
     * here we verify the need of ttl probes for active destinations
     */
    for (TTLFocusMap::iterator it = ttlfocus_map.begin(); it != ttlfocus_map.end(); ++it)
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

uint8_t TCPTrack::discernAvailScramble(Packet &pkt)
{
    /*
     * TODO - when we will integrate passive os fingerprint and
     * we will do a a clever study about different OS answers about
     * IP option, for every OS we will have or not the related support
     */
    uint8_t retval = SCRAMBLE_INNOCENT | SCRAMBLE_CHECKSUM | SCRAMBLE_MALFORMED;

    const TTLFocus &ttlfocus = ttlfocus_map.get(pkt);
    if (!(ttlfocus.status & (TTL_UNKNOWN | TTL_BRUTEFORCE)))
    {
        retval |= SCRAMBLE_TTL;
    }

    return retval;
}

/* 
 * injectHack is one of the core function in sniffjoke:
 *
 * the hacks are, for the most, three kinds.
 *
 * one kind requires the knowledge of the exact hop distance between the two
 * end points, to forge packets able to expire an hop before reaching the destination;
 * this permits to insert packet accepted in the session tracked by the sniffer.
 *
 * the second kind of hack does not have special requirements (as the third), 
 * and it's based on particular malformed ip/tcp options that would lead the real
 * destination peer to drop the fake packet.
 * 
 * the latter kind of attack works forging packets with a bad tcp checksum.
 *
 */
void TCPTrack::injectHack(Packet &origpkt)
{
    if (origpkt.ipfragment == true)
        return;

    bool removeOrig = false;

    SessionTrack &sessiontrack = sessiontrack_map.get(origpkt);

    vector<PluginTrack *> applicable_hacks;

    /*
     * Not all time we have a scramble available, we tell to the plugin which of
     * them are usable, and the packets is returned. the most of the time, all of
     * three scramble are available, and the plugins will use pktRandomDamage()
     * private method.
     */
    uint8_t availableScramble = discernAvailScramble(origpkt);

    origpkt.SELFLOG("Original packet - before hacks injection (availScramble %u)", availableScramble);

    /* SELECT APPLICABLE HACKS, the selection are base on:
     * 1) the plugin/hacks detect if the condition exists (eg: the hack wants a SYN and the packet is a RST+ACK)
     * 2) compute the percentage: mixing the hack-choosed and the user-choose  */
    for (vector<PluginTrack*>::iterator it = hack_pool.begin(); it != hack_pool.end(); ++it)
    {

        PluginTrack *hppe = *it;

        /*
         * this represents a preliminar check common to all hacks.
         * more specific ones related to the origpkt will be checked in
         * the Condition function implemented by a specific hack.
         */
        if (!(availableScramble & hppe->selfObj->supportedScramble))
        {
            origpkt.SELFLOG("no scramble available for %s", hppe->selfObj->hackName);
            continue;
        }

        bool applicable = true;
        applicable &= hppe->selfObj->Condition(origpkt, availableScramble);
        applicable &= percentage(
                                 sessiontrack.packet_number,
                                 hppe->selfObj->hackFrequency,
                                 runconfig.portconf[ntohs(origpkt.tcp->dest)]
                                 );

        if (applicable)
            applicable_hacks.push_back(hppe);
    }

    /* -- RANDOMIZE HACKS APPLICATION */
    random_shuffle(applicable_hacks.begin(), applicable_hacks.end());

    /* -- FINALLY, SEND THE CHOOSEN PACKET(S) */
    for (vector<PluginTrack *>::iterator it = applicable_hacks.begin(); it != applicable_hacks.end(); ++it)
    {

        PluginTrack *hppe = *it;

        hppe->selfObj->createHack(origpkt, availableScramble);

        for (vector<Packet*>::iterator hack_it = hppe->selfObj->pktVector.begin(); hack_it < hppe->selfObj->pktVector.end(); ++hack_it)
        {
            Packet &injpkt = **hack_it;
            /*
             * we trust in the external developer, but it's required a
             * simple safety check by sniffjoke :)
             */
            if (!injpkt.selfIntegrityCheck(hppe->selfObj->hackName))
            {
                LOG_ALL("invalid packet generated by hack %s", hppe->selfObj->hackName);

                injpkt.SELFLOG("bad integrity from: %s", hppe->selfObj->hackName);

                /* if you are running with --debug 6, I suppose you are the developing the plugins */
                if (runconfig.debug_level == PACKET_LEVEL)
                    RUNTIME_EXCEPTION("invalid packet generated from the hack");

                /* otherwise, the error was reported and sniffjoke continue to work */
                delete &injpkt;
                continue;
            }

            /*
             * here we set the evilbit http://www.faqs.org/rfcs/rfc3514.html
             * we are working in support RFC3514 and http://www.kill-9.it/rfc/draft-no-frills-tcp-04.txt too
             */
            if (injpkt.wtf != INNOCENT)
                injpkt.mark(LOCAL, EVIL);
            else
                injpkt.mark(LOCAL, GOOD);

            if (!lastPktFix(injpkt))
                continue;

            /* setting for debug pourpose: sniffjokectl info will show this value */
            sessiontrack.injected_pktnumber++;

            injpkt.SELFLOG("new generated packet by [%s], the original will be %s",
                           hppe->selfObj->hackName, hppe->selfObj->removeOrigPkt ? "REMOVED" : "KEEP");

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
                RUNTIME_EXCEPTION("BUG: invalid and impossibile");
            }
        }

        if (hppe->selfObj->removeOrigPkt == true)
        {
            removeOrig = true;
            /* reset the shared variable to the default */
            hppe->selfObj->removeOrigPkt = false;
        }

        hppe->selfObj->pktVector.clear();
    }

    /*
     * if almost an hack has requested origpkt deletion we drop it.
     * this has to be done here, at the end, to maximize the effect.
     */
    if (removeOrig == true)
    {
        origpkt.SELFLOG("Removing packet as request by the plugin");
        p_queue.remove(origpkt);
        delete &origpkt;
    }
}

/* 
 * lastPktFix is the last modification applied to packets.
 * modification involve only TCP packets coming from TUNNEL
 * and hacks injected in the queue to goes on the eth/wifi.
 *
 * p.s. if you are reading this piece of code for fix your sniffer:
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
 * hacks application it's applied in this order: PRESCRIPTION, MALFORMED, GUILTY.
 * a non applicable hack it's degraded to the next;
 * at worst GUILTY it's always applied.
 */
bool TCPTrack::lastPktFix(Packet &pkt)
{
    /* WHAT VALUE OF TTL GIVE TO THE PACKET ? */
    /*
     * here we call the map find();
     * the function returns end() if the ttlfocus it's not present.
     * in this situation and in situation where the focus status is
     * UNKNOWN or BRUTEFORCE the packet has TTL randomized in order
     * to don't disclose him real hop distance.
     */
    TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->daddr);
    if (it != ttlfocus_map.end() && (*it->second).status == TTL_KNOWN)
    {
        pkt.ip->ttl = (*it->second).ttl_estimate;
        if (pkt.wtf == PRESCRIPTION)
            pkt.ip->ttl -= (1 + (random() % 5)); /* [-1, -5], 5 values */
        else
            pkt.ip->ttl += (random() % 5); /* [+0, +4], 5 values */
    }
    else
    {
        pkt.ip->ttl += (random() % 20) - 10; /* [-10, +10 ], 20 mistification values */
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
        if (pkt.ipfragment == true || pkt.proto != TCP || RANDOMPERCENT(50))
        {
            if (!(pkt.injectIPOpts(/* corrupt ? */ true, /* strip previous options */ true)))
                pkt.SELFLOG("injectIPOpts failed to corrupt pkt");
            else
                malformed = true;
        }
        else
        {
            if (!(pkt.injectTCPOpts(/* corrupt ? */ true, /* strip previous options */ true)))
                pkt.SELFLOG("injectTCPOpts failed to corrupt pkt");
            else
                malformed = true;
        }

        if (!malformed)
        {
            if (ISSET_CHECKSUM(pkt.choosableScramble))
                pkt.wtf = GUILTY;
            else
                goto drop_packet;
        }
    }

    /* this is used because also good packet will have weird IP options */
    if (ISSET_MALFORMED(pkt.choosableScramble) && pkt.evilbit == GOOD)
    {
        if (RANDOMPERCENT(66))
            pkt.injectIPOpts(/* corrupt ? */ false, /* strip previous options ? */ false);
    }

    /* fixing the mangled packet */
    pkt.fixSum();

    /*
     * corrupted checksum application if required;
     * this is the last resort for hacks packets if neither
     * PRESCRIPTION nor MALFORMED are applicable.
     */
    if (pkt.wtf == GUILTY)
    {
        if (ISSET_CHECKSUM(pkt.choosableScramble))
            pkt.corruptSum();
        else
            goto drop_packet;
    }

    pkt.SELFLOG("packet ready to be send");
    return true;

drop_packet:
    pkt.SELFLOG("packet dropped: unable to apply fix before sending");
    delete &pkt;

    return false;
}

/* the packet is added in the packet queue here to be analyzed in a second time */
void TCPTrack::writepacket(source_t source, const unsigned char *buff, int nbyte)
{
    try
    {
        Packet * const pkt = new Packet(buff, nbyte);
        pkt->mark(source, INNOCENT, GOOD);

        p_queue.insert(*pkt, YOUNG);
    }
    catch (exception &e)
    {

        /* anomalous/malformed packets are flushed bypassing the queue */
        LOG_ALL("malformed original packet dropped: %s", e.what());
    }
}

/* 
 * this functions returns a packet from the SEND queue given a specific source
 */
Packet* TCPTrack::readpacket(source_t destsource)
{
    uint8_t mask;
    if (destsource == NETWORK)
        mask = NETWORK;
    else
        mask = TUNNEL | LOCAL | TTLBFORCE;

    Packet *pkt;

    p_queue.select(SEND);
    while ((pkt = p_queue.get()) != NULL)
    {
        if (pkt->source & mask)
        {
            p_queue.remove(*pkt);

            return pkt;
        }
    }

    return NULL;
}

bool TCPTrack::notifyIncoming(Packet &incompkt)
{
    bool removeOrig = false;

    /* SessionTrack &sessiontrack = sessiontrack_map.get(incompkt); */

    incompkt.SELFLOG("Original packet - before incoming Mangle");

    /* All the plugin have notified the incoming packet, simply, if 
     * the plugin don't need to check them, it return immediatly */
    for (vector<PluginTrack*>::iterator it = hack_pool.begin(); it != hack_pool.end(); ++it)
    {
        PluginTrack *hppe = *it;

        hppe->selfObj->mangleIncoming(incompkt);

        /* will be rare that mangleIncoming generare one or more packet, anyway is possibile */
        for (vector<Packet*>::iterator hack_it = hppe->selfObj->pktVector.begin(); hack_it < hppe->selfObj->pktVector.end(); ++hack_it)
        {
            Packet &injpkt = **hack_it;

            if (!injpkt.selfIntegrityCheck(hppe->selfObj->hackName))
            {
                LOG_ALL("invalid packet generated by hack %s", hppe->selfObj->hackName);

                injpkt.SELFLOG("bad integrity from: %s", hppe->selfObj->hackName);

                /* if you are running with --debug 6, I suppose you are the developing the plugins */
                if (runconfig.debug_level == PACKET_LEVEL)
                    RUNTIME_EXCEPTION("invalid packet generated from the hack");

                /* otherwise, the error was reported and sniffjoke continue to work */
                delete &injpkt;
                continue;
            }

            injpkt.mark(LOCAL, GOOD);

            /* lastPktFix is called because the checksum will not be correct */
            if (!lastPktFix(injpkt))
                continue;

            /* sessiontrack.injected_pktnumber++; */

            injpkt.SELFLOG("new generated packet from the Incoming of [%s], the original will be %s",
                           hppe->selfObj->hackName, hppe->selfObj->removeOrigPkt ? "REMOVED" : "KEEP");

            /* injpkt.position) is ignored in this section because mangleIncoming
             * is called on the YOUNG queue, and the current queue is YOUNG. a packet
             * generated from LOCAL is not handled, and, for the moment, is better
             * force the new queue of the injected packet in SEND. this cause that
             * every packet generated in mangleIncoming is equal to be POSTICIPATION */
            p_queue.insert(injpkt, SEND);
        }

        if (hppe->selfObj->removeOrigPkt == true)
        {
            removeOrig = true;
            /* reset the shared variable to the default */
            hppe->selfObj->removeOrigPkt = false;
        }

        hppe->selfObj->pktVector.clear();
    }

    /*
     * if almost an hack has requested incompkt deletion we drop it.
     * this has to be done here, at the end, to maximize the effect.
     */
    if (removeOrig == true)
    {
        incompkt.SELFLOG("Removing packet as request by the incoming manlger");
        return false;
    }
    else
        return true;
}

/*
 * in extraceTTLinfo we call the find() mathod of std::map because
 * we want to test the ttl existence and NEVER NEVER NEVER create a new one
 * to not permit an external packet to force us to activate a ttlbrouteforce session
 */
bool TCPTrack::extractTTLinfo(Packet &pkt)
{
    TTLFocusMap::iterator it;
    TTLFocus *ttlfocus;

    /* if the pkt is an ICMP TIME_EXCEEDED should contain informations useful for 
     * discern HOP distance from a remote host.  */
    if (pkt.proto == ICMP && pkt.icmp->type != ICMP_TIME_EXCEEDED)
    {
        const struct iphdr * const badiph = (struct iphdr *) ((unsigned char *) pkt.icmp + sizeof (struct icmphdr));
        const struct tcphdr * const badtcph = (struct tcphdr *) ((unsigned char *) badiph + (badiph->ihl * 4));

        /* we are looking only for our TCP expired pkts */
        if (badiph->protocol != IPPROTO_TCP)
            return true;

        /* if is not tracked, the user is making a tcptraceroute */
        if( (it = ttlfocus_map.find(badiph->daddr)) == ttlfocus_map.end() )
            return true;

        ttlfocus = it->second;

        const uint8_t expired_ttl = ntohs(badiph->id) - (ttlfocus->rand_key % 64);
        const uint8_t exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

        if (expired_ttl == exp_double_check)
        {
            if (ttlfocus->status == TTL_BRUTEFORCE)
            {
                pkt.SELFLOG("puppet %d Incoming ICMP EXPIRED, generated from %d",
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
            return false;
        }
    }

    /* if is not a TCP packet will not be useful for our */
    if(pkt.proto != TCP)
        return true;

    /* if is a TCP packet will contain important TTL information: 
     * ONLY if is already tracked */
    if( (it = ttlfocus_map.find(pkt.ip->daddr)) == ttlfocus_map.end() )
        return true;

    ttlfocus = it->second;

    /* a SYN ACK will be the answer at our probe! */
    if (pkt.tcp->syn && pkt.tcp->ack && (pkt.tcp->dest == htons(ttlfocus->puppet_port)) )
    {
        if (ttlfocus->status != TTL_BRUTEFORCE)
        {
            pkt.SELFLOG("weird: SYN+ACK from the puppet port in a session outside BForce");
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
        uint8_t discern_ttl = ntohl(pkt.tcp->ack_seq) - ttlfocus->rand_key - 1;

        ++ttlfocus->received_probe;

        if (discern_ttl < ttlfocus->ttl_estimate)
        {
            ttlfocus->ttl_estimate = discern_ttl;
            ttlfocus->ttl_synack = pkt.ip->ttl;
        }

        ttlfocus->status = TTL_KNOWN;

        pkt.SELFLOG("puppet %d Incoming SYN/ACK, estimated ttl %d received value %d", 
            ttlfocus->puppet_port, ttlfocus->ttl_estimate, ttlfocus->ttl_synack);
        ttlfocus->SELFLOG("puppet %d Incoming SYN/ACK, estimated ttl %d received value %d", 
            ttlfocus->puppet_port, ttlfocus->ttl_estimate, ttlfocus->ttl_synack);

        return false;
    }
    else
    {
        if (ttlfocus->status == TTL_KNOWN && ttlfocus->ttl_synack != pkt.ip->ttl)
        {
            /* probably a topology change has happened - we need a solution wtf!!  */
            pkt.SELFLOG("probable net topology change! #probe %u [ttl_estimate %u synack ttl %u this %u]",
                        ttlfocus->sent_probe, ttlfocus->ttl_estimate, ttlfocus->ttl_synack, pkt.ip->ttl);
        }
        return true;
    }
}

void TCPTrack::handleYoungPackets()
{
    /*
     * we analyze all YOUNG packets (received from NETWORK and from TUNNEL)
     *
     *   NETWORK packets:
     *     - we analyze icmp packet searching ttl informations (related to our ttlprobes).
     *     - we analyze tcp packet with various aims:
     *         1) acquire informations on possibile variations in ttl hops distance.
     *         2) verify the presence of a synack (related to our ttlprobes).
     *     - the packets are passed to the plugin because they will need to check
     *       or modify some information in them.
     *     - the packets after this analysis will be sent locally, because the packet
     *       coming from the gateway mac address will be dropped by the firewall rules.
     *
     *   TUNNEL packets:
     *     - we analyze tcp packets to see if the can marked sendable or if they need to be old
     *       in status KEEP waiting for some information.
     *       every packets from the tunnel will be associated to a session (and session counter updated)
     *       and to a ttlfocus (if the ttlfocus not exist a ttlbruteforce session will start).
     */
    Packet *pkt = NULL;

    if (runconfig.active)
    {
        for( p_queue.select(YOUNG); ((pkt = p_queue.getSource(NETWORK)) != NULL); )
        {
            /*
             * If is a packet triggered by the TTL_BRUTEFORCE's probe
             * If is a simple incoming packet:
             * Every incoming packet will have TTL information to update,
             * extractTTLinfo is a static member fixing the internal MAP
             */
            if(!extractTTLinfo(*pkt))
            {
                p_queue.remove(*pkt);
                delete &pkt;
                continue;
            }

            /* handling of mangleIncoming, is like the injectHack but
             * related to incoming packet */
            if(!notifyIncoming(*pkt))
            {
                p_queue.remove(*pkt);
                delete &pkt;
                continue;
            }

            p_queue.remove(*pkt);
            p_queue.insert(*pkt, SEND);
        }

        for( p_queue.select(YOUNG); ((pkt = p_queue.getSource(TUNNEL)) != NULL); )
        {
            /* the packet of a session under bruteforce is switched in KEEP queue */
            if (pkt->proto != TCP)
                continue;

            if (runconfig.use_blacklist && runconfig.blacklist->isPresent(pkt->ip->daddr) )
                continue;

            if (runconfig.use_whitelist && !runconfig.whitelist->isPresent(pkt->ip->daddr) )
                continue;

            /* return true when the packet is ready to be SEND */
            if(analyzeOutgoing(*pkt))
            {
                /* change the TTL and fix the checksum */
                lastPktFix(*pkt);
            }
        }
    }

    /* calling again the same p_queue.select act as "rewind" in the queue index */
    for( p_queue.select(YOUNG); ((pkt = p_queue.get()) != NULL); )
    {
        p_queue.remove(*pkt);
        p_queue.insert(*pkt, SEND);
    }
}

void TCPTrack::handleKeepPackets()
{
    /* we analyze every packet in KEEP queue to see if some can now be inserted in SEND queue */
    Packet *pkt = NULL;
    p_queue.select(KEEP);
    while ((pkt = p_queue.get()) != NULL)
    {
        if (ttlfocus_map.get(*pkt).status != TTL_BRUTEFORCE)
        {
            p_queue.remove(*pkt);
            if (lastPktFix(*pkt))
                p_queue.insert(*pkt, SEND);

            else
                RUNTIME_EXCEPTION("Fatal code [M4CH3T3]: please send a notification to the developers");
        }
    }

}

void TCPTrack::handleSendPackets()
{
    if (runconfig.active)
    {
        /* for every packet in SEND queue we insert some random hacks */
        Packet *pkt = NULL;

        p_queue.select(SEND);
        while ((pkt = p_queue.getSource(TUNNEL)) != NULL)
        {
            if (pkt->proto != TCP)
                continue;

            if (runconfig.use_blacklist && runconfig.blacklist->isPresent(pkt->ip->daddr) )
                continue;

            if (runconfig.use_whitelist && !runconfig.whitelist->isPresent(pkt->ip->daddr) )
                continue;

            injectHack(*pkt);
        }
    }
}

/* 
 *
 * this is an important and critical function for sniffjoke operativity.
 * 
 * analyzePacketQueue is called from the main.cc poll() block
 * 
 * all the functions that are called here inside a p_queue.get() cycle:
 *
 *     COULD  1) extract and delete the argument packet only,
 *            2) insert the argument packet or a new packet into any of the
 *               p_queue list. (because head insertion does not modify iterators)
 * 
 *     MUST:  1) not call functions containing a p_queue.get() as well.
 *
 * as defined in sniffjoke.h, the "status" variable could have these status:
 * YOUNG (packets received, here analyzed for the first time)
 * KEEP  (packets to keep in queue for some reason (for example until ttl brouteforce it's complete)
 * SEND (packets marked as sendable)
 */
void TCPTrack::analyzePacketQueue()
{
    /* if all queues are empy we have nothing to do */
    if (!p_queue.size())
        goto bypass_queue_analysis;

    handleYoungPackets();
    handleKeepPackets();
    handleSendPackets();

bypass_queue_analysis:

    /*
     * here we call sessiontrack_map and ttlfocus_map manage routines.
     * it's fundamental to do this here after SEND last_packet_fix()
     * and before ttl probes injections.
     * In fact the two routine, in case that their respective memory threshold
     * limits are passed, will delete the oldest records.
     * This is completely safe because send packets are just fixed and there
     * is no problem if we does not schedule a ttlprobe for a cycle;
     * KEEP packets will scatter a new ttlfocus at the next.
     */

    sessiontrack_map.manage();
    ttlfocus_map.manage();

    execTTLBruteforces();
}
