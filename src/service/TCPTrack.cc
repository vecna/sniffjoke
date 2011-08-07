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
#include "Scramble.h"

extern auto_ptr<UserConf> userconf;
extern auto_ptr<SessionTrackMap> sessiontrack_map;
extern auto_ptr<TTLFocusMap> ttlfocus_map;
extern auto_ptr<PluginPool> plugin_pool;
extern auto_ptr<Scramble> scramble;

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

/*
 * every kind of packet generation by external classess (plugin and scramble)
 * collect the packets in a vector<Packet *> as public member of the class.
 *
 * this method will parse these packet, verify integrity, and add properly 
 * in the TCPTrack.cc packet queue.
 *
 * the last argument is required only if the packets has to be added in a selected
 * queue type. otherwise, the Packet.position will be checked
 */
uint32_t TCPTrack::acquirePktVector(Packet &origpkt, vector<Packet *>srcpV, const char *info, queue_t wtf)
{
    uint32_t pktN = 0;

    for (vector<Packet*>::iterator input_it = srcpV.begin(); input_it < srcpV.end(); ++input_it)
    {
        Packet &pkt_gen = **input_it;

        if (!pkt_gen.selfIntegrityCheck(info))
        {
            pkt_gen.SELFLOG("%s: bad integrity", info);

            /* if you are running with --debug 6, I suppose you are the developing the bugged sw */
            if (userconf->runcfg.debug_level == PACKET_LEVEL)
                RUNTIME_EXCEPTION("%s: invalid pkt generated", info);
            else
                LOG_ALL("%s: invalid pkt generated", info);

            /* otherwise, the error was reported and sniffjoke continue to work */
            delete &pkt_gen;
            continue;
        }

        pkt_gen.SELFLOG("%s: injected new packet, generated by (i%u)", info, origpkt.SjPacketId);

        if(wtf != QUEUEUNASSIGNED) 
        {
            p_queue.insert(pkt_gen, wtf);
        }
        else
        {
            switch (pkt_gen.position)
            {
                case ANTICIPATION:
                    p_queue.insertBefore(pkt_gen, origpkt);
                    break;
                case POSTICIPATION:
                    p_queue.insertAfter(pkt_gen, origpkt);
                    break;
                case ANY_POSITION:
                    if (random() % 2)
                        p_queue.insertBefore(pkt_gen, origpkt);
                    else
                        p_queue.insertAfter(pkt_gen, origpkt);
                    break;
                case POSITIONUNASSIGNED:
                    RUNTIME_EXCEPTION("FATAL CODE [D4L1]: please send a notification to the developers");
            }
        }

        pktN++;
    }

    return pktN;
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

#if 1
        acquirePktVector(origpkt, pt->selfObj->pktVector, "incoming packet mangling", SEND);
#else
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
#endif

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

    /* XXX fixme: ci dovrebbe essere una SessionTrack che tenga traccia degli scramble usabili verso una certa destinazione
     * e qui andrebbe passato, non questa mask pupazzo */
    scrambleMask puppet_development_in_progress;

    puppet_development_in_progress += TTL;
    puppet_development_in_progress += CKSUM;
    /* XXX fine fixme */

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
         *
         *
        if ((!(availableScrambles & pt->selfObj->supportedScrambles)) && (userconf->runcfg.debug_level == PACKET_LEVEL))
        {
            char pluginavaileScrambStr[LARGEBUF] = {0};

            snprintfScramblesList(pluginavaileScrambStr, sizeof (pluginavaileScrambStr), pt->selfObj->supportedScrambles);

            origpkt.SELFLOG("%s: no scramble matching between system avail [%s] and plugins scramble [%s]",
                            pt->selfObj->pluginName, availableScramblesStr, pluginavaileScrambStr);
            continue;
        }
        
         */

        bool applicable = true;

        applicable &= pt->selfObj->condition(origpkt, puppet_development_in_progress);

        /* TODO: set a SniffJoke::initRandom() and a SniffJoke::randomQ(whenmark_t, Packet &) to linearize
         *       the percentage in scramble, plugin and configured weightness */
        applicable &= percentage(sessiontrack.outgoing.natural, pt->selfObj->pluginFrequency, getUserFrequency(origpkt));

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

        pt->selfObj->apply(origpkt, puppet_development_in_progress);

#if 1
        acquirePktVector(origpkt, pt->selfObj->pktVector, pt->selfObj->pluginName, QUEUEUNASSIGNED);
#else
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

            /* setting for debug pourpose: sniffjokectl info will show this value */
            sessiontrack.injected_pktnumber++;

            /* REMIND TODO VERIfY WHY XXX: perché questo ? */
            packet_filter.add(injpkt);
            /* REMIND TODO VERIfY WHY XXX: perché questo ? */

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
#endif

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
    bool retval = false;

    retval = scramble->applyScramble(BEFORE_CHECKSUM, pkt);
    acquirePktVector(pkt, scramble->scramblePktV, "scramble before cksum", QUEUEUNASSIGNED);

    if(retval)
        return true;

    retval = scramble->mystifyScramble(BEFORE_CHECKSUM, pkt);
    acquirePktVector(pkt, scramble->scramblePktV, "mystify before cksum", QUEUEUNASSIGNED);

    if(retval)
        return true;

    /* fixing the mangled packet */
    pkt.fixSum();

    retval = scramble->applyScramble(AFTER_CHECKSUM, pkt);
    acquirePktVector(pkt, scramble->scramblePktV, "scramble after cksum", QUEUEUNASSIGNED);

    if(retval)
        return true;

    scramble->mystifyScramble(AFTER_CHECKSUM, pkt);
    acquirePktVector(pkt, scramble->scramblePktV, "mystify after cksum", QUEUEUNASSIGNED);

    if(retval)
        return true;

#if 0
    /* if scramble was apply or the packet effectively don't need it, return true */
    if(retval /* || !pkt.needtocorrupt */ )
        return true;
#endif

    /* otherwise, a packet requiring a corruption, not corrupted must be signaled */
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
#if 0 // SCRAMBLE TODO XXX 
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
#endif
            (*pkt).SELFLOG("traveling to analyzeScramble after having cut off extractTTLinfo");

            ++(sessiontrack_map->get(*pkt).ingoing.natural);

            /* notify to the scramble the incoming packet */
            if (scramble->analyzeIncoming(*pkt))
            {
                pkt->SELFLOG("removal requested by scramble incoming filter");
                p_queue.drop(*pkt);
                continue;
            }

            /* here we notify each plugin of the arrival of a packet */
            if (notifyIncoming(*pkt))
            {
                pkt->SELFLOG("removal requested by plugins incoming filter");
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
                ++(sessiontrack_map->get(*pkt).outgoing.natural);

                /*
                 * only the scramble has the ability to choose if KEEP a packet, delaying 
                 * the session. vecna REMIND: neither TTL hack will strictly *require* this 
                 * waiting, because in fact we should start the first session without information
                 */

                if (scramble->isKeepRequired(*pkt))
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
 *       need to be hold in status KEEP waiting for some conditions. the 
 *       condtion will be choosed only by the scramble.
 *
 *   any other pkt->source does scatter a fatal exception.
 */
void TCPTrack::handleKeepPackets(void)
{
    Packet *pkt = NULL;
    for (p_queue.select(KEEP); ((pkt = p_queue.getSource(TUNNEL)) != NULL);)
    {
        if (scramble->isKeepRequired(*pkt))
            p_queue.insert(*pkt, HACK);
    }
}

/* -- SjInnerCore, yes, you read it well: In this function all the
 *    wozzy ghostbuster barbie girl will became packets with capital Evil.
 *
 * this is the method masking the call to the scramble, to the plugins
 * and manage deletion from the selected queue.
 */
void TCPTrack::SjInnerCore(Packet &pkt)
{
    if (scramble->applyScramble(BEFORE_HACK, pkt))
    {
        pkt.SELFLOG("removal requested by applyScramble [BEFORE_HACK]");
        p_queue.drop(pkt);
        return;
    }

    if (injectHack(pkt))
    {
        pkt.SELFLOG("removal requested by injectHack");
        p_queue.drop(pkt);
        return;
    }

    /* it contains applyScramble BEFORE_CHECKSUM and AFTER_CHECKSUM */
    if (!lastPktFix(pkt))
    {
        pkt.SELFLOG("pkt dropped because unable to be corrupted as request");
        p_queue.drop(pkt);
    }

    /* review this point: what about AFTER_HACK scramble ? */
}

/*
 * here we analyze HACK queue
 *
 * we handle only:
 *
 *   TUNNEL packets:
 *     - we analyze every packet, we fix and insert them into the SEND queue.
 *     TODO:
 *     - before apply the hack, the scramble handle them: the packets will change
 *       (whenmark_t = 
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
        SjInnerCore(*pkt);
    }

    for (p_queue.select(HACK); ((pkt = p_queue.getSource(SCRAMBLE)) != NULL);)
    {
        SjInnerCore(*pkt);
    }

    if (userconf->runcfg.chaining == true)
    {
        for (p_queue.select(HACK); ((pkt = p_queue.getSource(PLUGIN)) != NULL);)
        {
            if (pkt->chainflag == REHACKABLE)
            {
                pkt->SELFLOG("proposing the packet for the second round: chaining hack");
                SjInnerCore(*pkt);
            }
        }

        for (p_queue.select(HACK); ((pkt = p_queue.getSource(SCRAMBLE)) != NULL);)
        {
            SjInnerCore(*pkt);
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
             /*** morality, proto: check ? ***/
             /*** morality, proto: check ? ***/
        pkt->source = source;
        pkt->wtf = INNOCENT;

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
        mask = TUNNEL | PLUGIN | SCRAMBLE;

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

    scramble->periodicEvent();
}

