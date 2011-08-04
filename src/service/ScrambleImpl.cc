/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *
 *   Copyright (C) 2011
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
#include "Packet.h"
#include "Scramble.h"
// #include "ScrambleImpl.h"

extern auto_ptr<SessionTrackMap> sessiontrack_map;
extern auto_ptr<TTLFocusMap> ttlfocus_map;

/* here follow the classes of all scramble implemented in Sj */

class TTLScramble : public ScrambleImpl
{
protected:
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
    void injectTTLProbe(TTLFocus &ttlfocus)
    {
        Packet *injpkt;

        switch (ttlfocus.status)
        {
        case TTL_UNKNOWN:
            ttlfocus.status = TTL_BRUTEFORCE;
            /* do not break, continue inside TTL_BRUTEFORCE */
        case TTL_BRUTEFORCE:
            if (ttlfocus.sent_probe == /* userconf->runcfg.max_ttl_probe */ 32 )
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
                injpkt->source = SCRAMBLE;
                injpkt->wtf = INNOCENT;
                injpkt->ip->id = htons((ttlfocus.rand_key % 64) + ttlfocus.sent_probe);
                injpkt->ip->ttl = ttlfocus.sent_probe;
                injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttlfocus.sent_probe);

                injpkt->fixIPTCPSum();
//                p_queue.insert(*injpkt, SEND);

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
    void execTTLBruteforces(void)
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
    bool extractTTLinfo(const Packet &incompkt)
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

    bool apply(Packet &pkt)
    {
        TTLFocus &ttlfocus = ttlfocus_map->get(pkt);
        if (ttlfocus.status == TTL_KNOWN)
        {
            pkt.ip->ttl = ttlfocus.ttl_estimate - (1 + (random() % 2)); /* [-1, -2], 2 values */
        }

        pkt.wtf = CORRUPTDONE;
        return false;
    }

    bool mystification(Packet &pkt)
    {
        TTLFocus &ttlfocus = ttlfocus_map->get(pkt);
        if (ttlfocus.status == TTL_KNOWN)
        {
            pkt.ip->ttl = ttlfocus.ttl_estimate + (random() % 4); /* [+0, +3], 4 values */
        }
        return false;
    }

    bool isScrambleAvailable(Packet &pkt)
    {
        if ( ttlfocus_map->get(pkt).status == TTL_KNOWN )
            return true;
        else
            return false;
    }

    bool pktKeepRefresh(Packet &pkt)
    {
        return (ttlfocus_map->get(pkt).status == TTL_BRUTEFORCE);
    }

    bool periodicEvent(void)
    {
        execTTLBruteforces();
        return false;
    }

    TTLScramble(vector<Packet *> *SingletonScrambleV) :
    ScrambleImpl::ScrambleImpl(TTL, "TTL", SingletonScrambleV, false, BEFORE_CHECKSUM)
    {
    }

    ~TTLScramble(void)
    {
    }
};

class CKSUMScramble : public ScrambleImpl
{
    bool apply(Packet &pkt)
    {
        switch(pkt.proto)
        {
            case OTHER_IP:
                pkt.ip->check ^= 0xd3ad;
                pkt.wtf = CORRUPTDONE;
                break;
            case TCP:
                pkt.tcp->check ^= 0xd3ad;
                pkt.wtf = CORRUPTDONE;
                break;
            case UDP:
                pkt.udp->check ^= 0xd133;
                pkt.wtf = CORRUPTDONE;
                break;
            default:
                /* impossibile by isScrambleAvailable */
                break;
        }

        return false;
    }

    /* todo : come far selezionare uno scramble perché non venga chiamata la mist o l'apply ? */
    bool mystification(Packet &pkt)
    {
        return false;
    }

    bool isScrambleAvailable(Packet &pkt)
    {
        if( pkt.proto == TCP || pkt.proto == UDP )
            return true;
        else
            return false;
    }

    /* return true if the packet need to be keep in queue for the scramble pourpose */
    bool pktKeepRefresh(Packet &pkt)
    {
        return true;
    }

    bool periodicEvent(void)
    {
        return false;
    }

    CKSUMScramble(vector<Packet *> *SingletonScrambleV) :
    ScrambleImpl::ScrambleImpl(CKSUM, "CheckSum", SingletonScrambleV, false, AFTER_CHECKSUM)
    {
        LOG_VERBOSE("Loaded %s Scramble implementation", scrambleName);
    }

    ~CKSUMScramble(void)
    {
    }
};
