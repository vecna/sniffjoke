/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010 vecna <vecna@delirandom.net>
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
    LOG_VERBOSE("");
}

TCPTrack::~TCPTrack(void)
{
    LOG_VERBOSE("");
}

uint32_t TCPTrack::derivePercentage(uint32_t packet_number, uint16_t frequencyValue)
{
    uint32_t freqret = 0;

    if (frequencyValue & AGG_RARE)
    {
        freqret += 3;
    }
    if (frequencyValue & AGG_COMMON)
    {
        freqret += 7;
    }
    if (frequencyValue & AGG_ALWAYS)
    {
        freqret += 25;
    }
    if (frequencyValue & AGG_PACKETS10PEEK)
    {
        if (!(++packet_number % 10) || !(--packet_number % 10) || !(--packet_number % 10))
            freqret += 10;
        else
            freqret += 1;
    }
    if (frequencyValue & AGG_PACKETS30PEEK)
    {
        if (!(++packet_number % 30) || !(--packet_number % 30) || !(--packet_number % 30))
            freqret += 10;
        else
            freqret += 1;
    }
    if (frequencyValue & AGG_TIMEBASED5S)
    {
        if (!((uint8_t) sj_clock % 5))
            freqret += 12;
        else
            freqret += 1;
    }
    if (frequencyValue & AGG_TIMEBASED20S)
    {
        if (!((uint8_t) sj_clock % 20))
            freqret += 12;
        else
            freqret += 1;
    }
    if (frequencyValue & AGG_STARTPEEK)
    {
        if (packet_number < 20)
            freqret += 10;
        else if (packet_number < 40)
            freqret += 5;
        else
            freqret += 1;
    }
    if (frequencyValue & AGG_LONGPEEK)
    {
        if (packet_number < 60)
            freqret += 8;
        else if (packet_number < 120)
            freqret += 4;
        else
            freqret += 1;
    }

    return freqret;
}

/*  
 *  this function is used from the inject_hack_in_queue() routine for decretee
 *  the possibility for an hack to happen.
 *  returns true if it's possibile to forge the hack.
 *  the calculation involves:
 *   - the session packet count is a variable inside the equation (some hacks are 
 *     configured to act in peek time or packets number relationship)
 *   - the frequency selection provide from the hack programmer: is used when the 
 *     port-aggressivity.conf file don't provide a specific configuration.
 *   - the port configuration settings: derived from 'port-aggressivity.conf' 
 */
bool TCPTrack::percentage(uint32_t packet_number, uint16_t hackFrequency, uint16_t userFrequency)
{
    uint32_t this_percentage = 0, aggressivity_percentage = 0;
    uint16_t referenceFrequency;

    /* the frequency is sets by default, if not provided by the user. the aggressivity is sets
     * by the plugin developer, if is not used.  */
    if (!(aggressivity_percentage = derivePercentage(packet_number, userFrequency)))
    {
        /* this happen in --only-plugin (and the forced frequency to AGG_ALWAYS), not
         * FREQ_ is provived and this cause an error, for this reason, I add the default
         * FREQ_NORMAL here */
        hackFrequency += FREQ_NORMAL;
        referenceFrequency = hackFrequency;
        aggressivity_percentage = derivePercentage(packet_number, hackFrequency);
    }
    else
    {
        referenceFrequency = userFrequency;
    }

    if (referenceFrequency & FREQ_NONE)
    {
        /* when aggressivity match set to "10", now is 0% of probability */
        this_percentage = aggressivity_percentage * 0;
    }
    else if (referenceFrequency & FREQ_LIGHT)
    {
        /* with 10 ("common") is 40% of probability */
        this_percentage = aggressivity_percentage * 4;
    }
    else if (referenceFrequency & FREQ_NORMAL)
    {
        /* with 10 ("common") is 80% of probability */
        this_percentage = aggressivity_percentage * 8;
    }
    else if (referenceFrequency & FREQ_HEAVY)
    {
        /* with 10 ("common") is 120% of probabilty, this was useful when a 
         * float value was used, better analysis will improve this algoritm */
        this_percentage = aggressivity_percentage * 12;
    }
    else
    {
        /* this is happen and I didn't understand why, so, I try to log */
        LOG_DEBUG("arbitrary added percentage: no FREQ_ are present. (this prcnt %d) user %u hack %u", this_percentage, hackFrequency, userFrequency);
        this_percentage = aggressivity_percentage * 3;
    }

    return (((uint32_t) (random() % 100) + 1 <= this_percentage));
}

/*
 * analyze an incoming icmp packet.
 * at the moment, the unique icmp packet analyzed is the ICMP_TIME_EXCEEDED;
 * a TIME_EXCEEDED packet shoulds contain informations to discern HOP distance
 * from a remote host.
 */
bool TCPTrack::analyze_incoming_icmp(Packet &pkt)
{
    if (pkt.icmp->type != ICMP_TIME_EXCEEDED)
        return true;

    const struct iphdr * const badiph = (struct iphdr *) ((unsigned char *) pkt.icmp + sizeof (struct icmphdr));
    const struct tcphdr * const badtcph = (struct tcphdr *) ((unsigned char *) badiph + (badiph->ihl * 4));

    if (badiph->protocol == IPPROTO_TCP)
    {
        /*
         * here we call the find() method of std::map because
         * we want to test the ttl existence and NEVER NEVER NEVER create a new one
         * to not permit an external packet to force us to activate a ttlbrouteforce session.
         * This is not a real sentence, due to the reason to have a stateless
         * behaviour we can start a ttlprobe stage (and also initialize a session)
         * for every packets we will output (not input);
         *
         * for example we could start a ttlbrobe also if we receive a syn from the network
         * and our kernel schedule a response packet.
         * i don't think this a problem due to the strong control implementation on the map size.
         */
        TTLFocusMap::iterator it = ttlfocus_map.find(badiph->daddr);
        if (it != ttlfocus_map.end())
        {
            TTLFocus *ttlfocus = it->second;
            const uint8_t expired_ttl = ntohs(badiph->id) - (ttlfocus->rand_key % 64);
            const uint8_t exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

            if (expired_ttl == exp_double_check)
            {

                snprintf(pkt.debug_buf, sizeof (pkt.debug_buf), "puppet %d Incoming ICMP EXPIRED, generated from %d",
                         ttlfocus->puppet_port, expired_ttl);
                pkt.selflog(__func__, pkt.debug_buf);

                ttlfocus->received_probe++;

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

                snprintf(ttlfocus->debug_buf, sizeof (ttlfocus->debug_buf),
                         "expired_ttl from ICMP: %d, puppet %u", expired_ttl, ttlfocus->puppet_port);
                ttlfocus->selflog(__func__, NULL);

                /*
                 * the expired icmp scattered due to our ttl probes,
                 * so we can trasparently remove it.
                 */
                p_queue.remove(pkt);
                delete &pkt;
                return false;
            }
        }
    }

    return true;
}

/*
 * this function analyzes the ttl of an incoming tcp packet to discriminate
 * a topology hop change;
 * at the time it's only used for stat's reasons.
 */
void TCPTrack::analyze_incoming_tcp_ttl(Packet &pkt)
{
    /*
     * Here we call the find() mathod of std::map because
     * we want to test the ttl existence and NEVER NEVER NEVER create a new one
     * to not permit an external packet to force us to activate a ttlbrouteforce session
     */
    TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->saddr);
    if (it != ttlfocus_map.end())
    {
        TTLFocus *ttlfocus = it->second;
        if (ttlfocus->status == TTL_KNOWN && ttlfocus->ttl_synack != pkt.ip->ttl)
        {
            /* probably a topology change has happened - we need a solution wtf!!  */
            snprintf(pkt.debug_buf, sizeof (pkt.debug_buf),
                     "probable net topology change! #probe %u [ttl_estimate %u synack ttl %u]",
                     ttlfocus->sent_probe, ttlfocus->ttl_estimate, ttlfocus->ttl_synack
                     );
            pkt.selflog(__func__, pkt.debug_buf);
        }
    }
}

/*
 * this function analyzes the a tcp syn+ack;
 * due to the ttlbruteforce stage a syn + ack will scatter for ttl >= expiring, so if the received packet
 * matches the puppet port used for the current ttlbruteforce session we can discern the ttl as:
 *     
 *     unsigned char discern_ttl =  ntohl(pkt.tcp->ack_seq) - ttlfocus->rand_key - 1;
 */
bool TCPTrack::analyze_incoming_tcp_synack(Packet &pkt)
{
    /*
     * here we call the find() mathod of std::map for the same reason as for
     * the analyze_incoming_icmp() routine.
     * refer to comments inside analyze_incoming_icmp().
     */
    TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->saddr);
    if (it != ttlfocus_map.end())
    {
        TTLFocus * const ttlfocus = it->second;

        if (pkt.tcp->dest == htons(ttlfocus->puppet_port))
        {
            snprintf(pkt.debug_buf, sizeof (pkt.debug_buf), "puppet %d Incoming SYN/ACK", ttlfocus->puppet_port);
            pkt.selflog(__func__, pkt.debug_buf);

            uint8_t discern_ttl = ntohl(pkt.tcp->ack_seq) - ttlfocus->rand_key - 1;

            ++ttlfocus->received_probe;

            if (discern_ttl < ttlfocus->ttl_estimate)
            {
                ttlfocus->ttl_estimate = discern_ttl;
                ttlfocus->ttl_synack = ntohs(pkt.ip->ttl);
            }

            ttlfocus->status = TTL_KNOWN;

            ttlfocus->selflog(__func__, NULL);

            /*
             * the syn+ack scattered due to our ttl probes,
             * so we can trasparently remove it
             */
            p_queue.remove(pkt);
            delete &pkt;
            return false;
        }
    }

    return true;
}

/*
 * this function analyzes outgoing packets.
 * returns:
 *   - true if the packet could be SEND;
 *   - false if the bruteforce stage is active.
 */
bool TCPTrack::analyze_outgoing(Packet &pkt)
{
    SessionTrack &sessiontrack = sessiontrack_map.get(pkt);
    ++sessiontrack.packet_number;

    const TTLFocus &ttlfocus = ttlfocus_map.get(pkt);
    if (ttlfocus.status == TTL_BRUTEFORCE)
    {
        p_queue.remove(pkt);
        p_queue.insert(pkt, KEEP);
        return false;
    }

    return true;
}

/*
 * this function analyzes KEEP packets.
 * returns:
 *   - true if the packet could be SEND;
 *   - false if the bruteforce stage is active.
 */
bool TCPTrack::analyze_keep(Packet &pkt)
{
    const TTLFocus &ttlfocus = ttlfocus_map.get(pkt);
    if (ttlfocus.status == TTL_BRUTEFORCE)
        return false;

    return true;
}

/* 
 * This function is responsible of the ttl bruteforce stage used
 * to detect the hop distance between us and the remote peer
 * 
 * Sniffjoke uses the first session packet seen as a starting point
 * for this stage.
 * 
 * Packets generated are a copy of the original (firt seen) packet
 * with some little modifications to:
 *  - ip->id
 *  - ip->ttl
 *  - tcp->source
 *  - tcp->seq
 * 
 */
void TCPTrack::inject_ttlprobe_in_queue(TTLFocus &ttlfocus)
{
    if (ttlfocus.sent_probe == MAX_TTLPROBE)
    {
        ttlfocus.status = TTL_UNKNOWN;
        ttlfocus.sent_probe = 0;
        ttlfocus.received_probe = 0;
        ttlfocus.ttl_estimate = 0xFF;
        ttlfocus.ttl_synack = 0;
        /* retry scheduled in 10 minutes */
        ttlfocus.next_probe_time = sj_clock + 600;
        return;
    }

    Packet *injpkt;

    switch (ttlfocus.status)
    {
    case TTL_UNKNOWN:
        ttlfocus.status = TTL_BRUTEFORCE;
        /* do not break, continue inside TTL_BRUTEFORCE */
    case TTL_BRUTEFORCE:
        ++ttlfocus.sent_probe;
        injpkt = new Packet(ttlfocus.probe_dummy);
        injpkt->mark(TTLBFORCE, INNOCENT, GOOD);
        injpkt->ip->id = (ttlfocus.rand_key % 64) + ttlfocus.sent_probe;
        injpkt->ip->ttl = ttlfocus.sent_probe;
        injpkt->tcp->source = htons(ttlfocus.puppet_port);
        injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttlfocus.sent_probe);

        injpkt->fixIpTcpSum();
        p_queue.insert(*injpkt, SEND);

        snprintf(injpkt->debug_buf, sizeof (injpkt->debug_buf), "TTL_BRUTEFORCE probe# %u [ttl_estimate %u]",
                 ttlfocus.sent_probe, ttlfocus.ttl_estimate);

        /* the next ttl probe schedule is forced in the next cycle */
        ttlfocus.next_probe_time = sj_clock;

        injpkt->selflog(__func__, injpkt->debug_buf);
        break;
    case TTL_KNOWN:
        /* TODO: Handle the KNOWN status; find a way to detect network topology changes. */
        break;
    }
}

uint8_t TCPTrack::discernAvailScramble(Packet &pkt)
{
    uint8_t retval = 0;

    /*
     * TODO - when we will integrate passive os fingerprint and
     * we will do a a clever study about different OS answer about
     * IP option, for every OS we will have or not the related support
     */
    retval = SCRAMBLE_CHECKSUM | SCRAMBLE_INNOCENT | SCRAMBLE_MALFORMED;

    const TTLFocus &ttlfocus = ttlfocus_map.get(pkt);
    if (!(ttlfocus.status & (TTL_UNKNOWN | TTL_BRUTEFORCE)))
    {
        retval |= SCRAMBLE_TTL;
    }

    return retval;
}

/* 
 * inject_hack_in_queue is one of the core function in sniffjoke:
 *
 * the hacks are, for the most, three kinds.
 *
 * one kind requires the knowledge of exactly hop distance between the two
 * end points, to forge packets able to expire an hop before the destination IP address;
 * this permit to insert packet accepted in the session tracked by the sniffer.
 *
 * the second kind of hack does not have special requirements (as the third), 
 * and it's based on particular malformed ip/tcp options that would lead the real
 * destination peer to drop the fake packet.
 * 
 * the latter kind of attack works forging packets with a bad tcp checksum.
 *
 */
void TCPTrack::inject_hack_in_queue(Packet &origpkt)
{
    if (origpkt.ipfragment == true)
        return;

    bool removeOrig = false;

    const SessionTrack &sessiontrack = sessiontrack_map.get(origpkt);

    vector<PluginTrack *> applicable_hacks;

    /*
     * Not all time we have a scramble available, we tell to the plugin which of
     * them are usable, and the packets is returned. the most of the time, all of
     * three scramble are available, and the plugins will use pktRandomDamage()
     * private method.
     */
    uint8_t availableScramble = discernAvailScramble(origpkt);

    snprintf(origpkt.debug_buf, sizeof (origpkt.debug_buf), "OrigPKT");
    origpkt.selflog(__func__, origpkt.debug_buf);

    /* SELECT APPLICABLE HACKS */
    for (vector<PluginTrack*>::iterator it = hack_pool.begin(); it != hack_pool.end(); ++it)
    {
        PluginTrack *hppe = *it;
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

                snprintf(injpkt.debug_buf, sizeof (injpkt.debug_buf), "bad integrity from: %s", hppe->selfObj->hackName);
                injpkt.selflog(__func__, injpkt.debug_buf);

                /* if you are running with --debug 6, I suppose you are the developing the plugins */
                if (runconfig.debug_level == PACKET_LEVEL)
                    RUNTIME_EXCEPTION("invalid packet generated from the hack");

                /* otherwise, the error was reported and sniffjoke continue to work */
                delete &injpkt;
                continue;
            }

            if (!last_pkt_fix(injpkt))
            {
                snprintf(injpkt.debug_buf, sizeof (injpkt.debug_buf), "unable to scramble (%s)", hppe->selfObj->hackName);
                injpkt.selflog(__func__, injpkt.debug_buf);

                delete &injpkt;
                continue;
            }

            /*
             * here we set the evilbit http://www.faqs.org/rfcs/rfc3514.html
             * we are working in support RFC3514 and http://www.kill-9.it/rfc/draft-no-frills-tcp-04.txt too
             */
            injpkt.mark(LOCAL, EVIL);

            snprintf(injpkt.debug_buf, sizeof (injpkt.debug_buf), "HackPKT (%s)", hppe->selfObj->hackName);
            injpkt.selflog(__func__, injpkt.debug_buf);

            switch (injpkt.position)
            {
            case ANTICIPATION:
                p_queue.insert_before(injpkt, origpkt);
                break;
            case POSTICIPATION:
                p_queue.insert_after(injpkt, origpkt);
                break;
            case ANY_POSITION:
                if (random() % 2)
                    p_queue.insert_before(injpkt, origpkt);
                else
                    p_queue.insert_after(injpkt, origpkt);
                break;
            case POSITIONUNASSIGNED:
                RUNTIME_EXCEPTION("invalid and impossibile");
            }
        }

        if (hppe->selfObj->removeOrigPkt == true)
            removeOrig = true;

        hppe->selfObj->pktVector.clear();
    }

    /*
     * If almost an hack has requested origpkt deletion we drop it.
     * This has to be done here, at the end, to maximize the effect.
     */
    if (removeOrig == true)
    {
        p_queue.remove(origpkt);
        delete &origpkt;
    }
}

/* 
 * last_pkt_fix is the last modification applied to packets.
 * Modification involve only TCP packets coming from TUNNEL
 * and hacks injected in the queue.
 *
 * p.s. if you are reading this piece of code for fix your sniffer:
 *   we SHALL BE YOUR NIGHTMARE.
 *   we SHALL BE YOUR NIGHTMARE.
 *   we SHALL BE YOUR NIGHTMARE, LOSE ANY HOPE, we HAD THE RANDOMNESS IN OUR SIDE.
 *
 *
 * 
 *   PRESCRIPTION: will EXPIRE BEFORE REACHING destination (due to ttl modification)
 *             could be: ONLY EVIL PACKETS
 *   GUILTY:       will BE DISCARDED by destination (due to some error introduction)
 *                      at the moment the only error applied is the invalidation tcp checksum
 *                      could be: ONLY EVIL PACKETS 
 *   MALFORMED:    will BE DISCARDED by destination due to misuse of ip options
 *               could be: ONLY EVIL PACKETS
 *   INNOCENT:       will BE ACCEPTED, so, INNOCENT but EVIL cause the same treatment of a
 *               GOOD packet.
 *
 *
 * Hacks application it's applied in this order: PRESCRIPTION, MALFORMED, GUILTY.
 * A non applicable hack it's degraded to the next;
 * At worst GUILTY it's always applied.
 * 
 *
 */
bool TCPTrack::last_pkt_fix(Packet &pkt)
{
    /* WHAT VALUE OF TTL GIVE TO THE PACKET ? */
    /*
     * here we call the map find();
     * the function returns end() if the ttlfocus it's not present.
     * In this situation and in situation where the focus status is
     * UNKNOWN or BRUTEFORCE the packet has TTL randomized in order
     * to don't disclose him real hop distance.
     */
    TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->daddr);
    if (it != ttlfocus_map.end() && !((*it->second).status & (TTL_UNKNOWN | TTL_BRUTEFORCE)))
    {
        if (pkt.wtf == PRESCRIPTION)
            pkt.ip->ttl = (*it->second).ttl_estimate - (random() % 4) - 1; /* [-1, -5], 5 values */
        else
            pkt.ip->ttl = (*it->second).ttl_estimate + (random() % 4); /* [+0, +4], 5 values */
    }
    else
    {
        pkt.ip->ttl += (random() % 20) - 10;
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
        /* IP options, every packet subject if possible, and MALFORMED will be applied */
        if (!(pkt.Inject_IPOPT(/* corrupt ? */ true, /* strip previous options */ true)))
        {
            pkt.selflog(__func__, "IPOPT failed in corrupt header");

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
            pkt.Inject_IPOPT(/* corrupt ? */ false, /* strip previous options ? */ false);
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
        {
            pkt.corruptSum();
        }
        else
        {
            goto drop_packet;
        }
    }

    pkt.selflog(__func__, "Packet ready to be send");
    return true;
drop_packet:
    pkt.selflog(__func__, "Packet dropped: unable to apply fix before sending");
    return false;
}

/* the packet is added in the packet queue for be analyzed in a second time */
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

/* 
 *
 * this is an important and critical function for sniffjoke operativity.
 * 
 * analyze_packets_queue is called from the main.cc poll() block
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
 * 
 */
void TCPTrack::analyze_packets_queue()
{
    /* if all queues are empy we have nothing to do */
    if (!p_queue.size())
        goto bypass_queue_analysis;

    Packet *pkt;

    /*
     * we analyze all YOUNG packets (received from NETWORK and from TUNNEL)
     *
     *   NETWORK packets:
     *     - we analyze icmp packet searching ttl informations (related to our ttlprobes).
     *     - we analyze tcp packet with various aims:
     *         1) acquire informations on possibile variations in ttl hops distance.
     *         2) verify the presence of a synack (related to our ttlprobes).
     *     - all packets if not destroyed will be marked send.
     *
     *   TUNNEL packets:
     *     - we analyze tcp packets to see if the can marked sendable or if they need to be old
     *       in status KEEP waiting for some information.
     *       every packets from the tunnel will be associated to a session (and session counter updated)
     *       and to a ttlfocus (if the ttlfocus does not currently exist a ttlbrouteforce session will start).
     */
    p_queue.select(YOUNG);
    while ((pkt = p_queue.get()) != NULL)
    {
        bool send = true;
        if (pkt->source == NETWORK)
        {
            if (pkt->proto == ICMP)
            {
                send = analyze_incoming_icmp(*pkt);
            }
            else if (pkt->proto == TCP)
            {
                /* analysis of the incoming TCP packet for check if TTL we are receiving is
                 * changed or not. is not the correct solution for detect network topology
                 * change, but we need it! */
                analyze_incoming_tcp_ttl(*pkt);

                send = analyze_incoming_tcp_synack(*pkt);
            }
        }
        else /* pkt->source == TUNNEL */
        {
            /* the check is based in blacklist, whitelist. the port and protocol is checked inside the
             * "Condition(" imported function. so, every session accepted after this point will be 
             * ttl bruteforced and mangled by weird IP/TCP options */
            if (pkt->proto == TCP)
            {
                if (runconfig.use_blacklist)
                {
                    if (!(runconfig.blacklist->isPresent(pkt->ip->daddr)))
                    {
                        sprintf(pkt->debug_buf, "blacklist setting is present: IP address don't match");
                        pkt->selflog(__func__, pkt->debug_buf);
                        send = analyze_outgoing(*pkt);
                    }
                    else
                    {
                        sprintf(pkt->debug_buf, "blacklist setting is present: IP address match and is not hacked");
                        pkt->selflog(__func__, pkt->debug_buf);
                    }
                }
                else if (runconfig.use_whitelist)
                {
                    if (runconfig.whitelist->isPresent(pkt->ip->daddr))
                    {
                        sprintf(pkt->debug_buf, "whitelist setting is present: IP address match");
                        pkt->selflog(__func__, pkt->debug_buf);
                        send = analyze_outgoing(*pkt);
                    }
                    else
                    {
                        sprintf(pkt->debug_buf, "whitelist setting is present: IP address don't match and is not hacked");
                        pkt->selflog(__func__, pkt->debug_buf);
                    }
                }
                else
                {
                    send = analyze_outgoing(*pkt);
                }
            }
        }

        if (send == true)
        {
            p_queue.remove(*pkt);
            if (pkt->source == NETWORK || pkt->proto != TCP || last_pkt_fix(*pkt))
                p_queue.insert(*pkt, SEND);
            else
                RUNTIME_EXCEPTION("");
        }
    }

    /* we analyze every packet in KEEP queue to see if some can now be inserted in SEND queue */
    p_queue.select(KEEP);
    while ((pkt = p_queue.get()) != NULL)
    {
        bool send = analyze_keep(*pkt);
        if (send == true)
        {
            p_queue.remove(*pkt);
            if (last_pkt_fix(*pkt))
                p_queue.insert(*pkt, SEND);
            else
                RUNTIME_EXCEPTION("");
        }
    }

    /* for every packet in SEND queue we insert some random hacks */
    p_queue.select(SEND);
    while ((pkt = p_queue.get()) != NULL)
    {
        if (pkt->source == TUNNEL && pkt->proto == TCP)
            inject_hack_in_queue(*pkt);
    }

bypass_queue_analysis:

    /*
     * here we call sessiontrack_map and ttlfocus_map manage routine.
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

    /*
     * here we verify the need of ttl probes for active destinations
     */
    for (TTLFocusMap::iterator it = ttlfocus_map.begin(); it != ttlfocus_map.end(); ++it)
    {
        TTLFocus &ttlfocus = *((*it).second);
        if ((ttlfocus.status != TTL_KNOWN)
                && (ttlfocus.access_timestamp > sj_clock - 30)
                && (ttlfocus.next_probe_time <= sj_clock))
        {
            inject_ttlprobe_in_queue(*(*it).second);
        }
    }
}
