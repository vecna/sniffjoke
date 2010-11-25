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

#define TTLFOCUS_EXPIRETIME		604800	/* access expire time in seconds (1 WEEK) */
#define SESSIONTRACK_EXPIRETIME		1200	/* access expire time in seconds (5 MINUTES) */

TCPTrack::TCPTrack(sj_config& runcfg, HackPool& hpp) :
	runconfig(runcfg),
	hack_pool(hpp)
{
	debug.log(VERBOSE_LEVEL, __func__);
	
	/* random pool initialization */
	for (int i = 0; i < ((random() % 40) + 3); i++) 
		srandom((unsigned int)time(NULL) ^ random());
		
	ttlfocus_map.load(runconfig.ttlfocuscache_file);
}

TCPTrack::~TCPTrack(void) 
{
	debug.log(VERBOSE_LEVEL, __func__);
	ttlfocus_map.dump(runconfig.ttlfocuscache_file);
}

/*  
 *  this function is used from the sniffjoke routing for decretee the possibility for
 *  an hack to happen.
 *  the calculation involves:
 *   - the session packet_number, because for example hacks must happen, for the most,
 *     at the start of the session (between the first 10 packets),
 *   - a specifi frequency selector provided by hacks programmer.
 *   - a port strengh selector (none|light|normal|heavy) defined in running configuration
 */
bool TCPTrack::percentage(unsigned int packet_number, Frequency freqkind, Strength weightness)
{
	unsigned int this_percentage = 0, freqret = 0;
	switch(freqkind) {
		case RARE:
			freqret = 3;
			break;
		case COMMON:
			freqret = 7;
			break;
		case PACKETS10PEEK:
			if(!(++packet_number % 10) || !(--packet_number % 10) || !(--packet_number % 10))
				freqret = 10;
			else
				freqret = 1;
			break;
		case PACKETS30PEEK:
			if(!(++packet_number % 30) || !(--packet_number % 30) || !(--packet_number % 30))
				freqret = 10;
			else
				freqret = 1;
			break;
		case TIMEBASED5S:
			if(!((unsigned int)clock.tv_sec % 5))
				freqret = 12;
			else
				freqret = 1;
			break;
		case TIMEBASED20S:
			if(!((unsigned int)clock.tv_sec % 20))
				freqret = 12;
			else
				freqret = 1;
			break;
		case STARTPEEK:
			if(packet_number < 20)
				freqret = 10;
			else if (packet_number < 40)
				freqret = 5;
			else
				freqret = 1;
			break;
		case LONGPEEK:
			if(packet_number < 60)
				freqret = 8;
			else if (packet_number < 120)
				freqret = 4;
			else
				freqret = 1;
			break;
		case FREQUENCYUNASSIGNED:
                        debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
                        SJ_RUNTIME_EXCEPTION("");
			break;
	}

	/* the "NORMAL" transform a freqret of "10" in 80% of hack probability */
	switch(weightness) {
		case NONE:
			this_percentage = freqret * 0;
			break;
		case LIGHT:
			this_percentage = freqret * 4;
			break;
		case NORMAL:
			this_percentage = freqret * 8;
			break;
		case HEAVY:
			this_percentage = freqret * 12;
			break;
	}

	return (((unsigned int)(random() % 100) + 1 <= this_percentage));
}


/* 
 * This function is responsible of the ttl bruteforce phase.
 * 
 * Sniffjoke use the first session packet (the SYN) as a starting point
 * for this phase. 
 * Here are forged traceroute packets used for ttl detection between our peer
 * and the remote peer. 
 * 
 * Packets generated are a copy of the original syn packet with some little
 * modifications to:
 *  - ip->id
 *  - ip->ttl
 *  - tcp->source
 *  - tcp->seq
 * 
 * the checksum fix is delegated to last_pkt_fix()
 */
void TCPTrack::inject_ttlprobe_in_queue(TTLFocus &ttlfocus)
{
	/* if the ttlfocus is not accessed from more than 30 seconds or the probe interval is not passed we return immediatly */
	if((ttlfocus.access_timestamp < clock.tv_sec - 30) || !ttlfocus.isProbeIntervalPassed(clock))
		return;

	if (ttlfocus.sent_probe == runconfig.max_ttl_probe) {
		ttlfocus.status = TTL_UNKNOWN;
		return;
	}

	if(ttlfocus.status == TTL_BRUTEFORCE) {
		ttlfocus.sent_probe++;
		Packet *injpkt = new Packet(ttlfocus.probe_dummy);
		injpkt->mark(TTLBFORCE, INNOCENT, GOOD);
		injpkt->ip->id = (ttlfocus.rand_key % 64) + ttlfocus.sent_probe;
		injpkt->ip->ttl = ttlfocus.sent_probe;
		injpkt->tcp->source = ttlfocus.puppet_port;
		injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttlfocus.sent_probe);
		p_queue.insert(Q_PRIORITY_SEND, *injpkt);
			
		snprintf(injpkt->debug_buf, sizeof(injpkt->debug_buf), "Injecting probe %d [exp %d min work %d]",
			ttlfocus.sent_probe, ttlfocus.expiring_ttl, ttlfocus.min_working_ttl
		);
		
		injpkt->selflog(__func__, injpkt->debug_buf);
		
		/* the bruteforce is scheduled with 50ms interval */
		ttlfocus.scheduleNextProbe50ms();		

	} else if (ttlfocus.status == TTL_KNOWN) {		
		ttlfocus.sent_probe++;

		ttlfocus.selectPuppetPort();
		
		ttlfocus.synack_ttl = 0;
		ttlfocus.sent_probe = 0;
		ttlfocus.received_probe = 0;
			
		unsigned int pkts = 5;
		unsigned int ttl = ttlfocus.min_working_ttl > 5 ? ttlfocus.min_working_ttl - 5 : 0;
		while(pkts--) {
			Packet *injpkt = new Packet(ttlfocus.probe_dummy);
			injpkt->mark(TTLBFORCE, INNOCENT, GOOD);
			ttlfocus.sent_probe++;
			injpkt->ip->id = (ttlfocus.rand_key % 64) + ttl;
			injpkt->ip->ttl = ttl;
			injpkt->tcp->source = ttlfocus.puppet_port;
			injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttl);
			p_queue.insert(Q_PRIORITY_SEND, *injpkt);
			ttl++;
				
			snprintf(injpkt->debug_buf, sizeof(injpkt->debug_buf), "Injecting probe %d [exp %d min work %d]",
				ttlfocus.sent_probe, ttlfocus.expiring_ttl, ttlfocus.min_working_ttl
			);
				
			injpkt->selflog(__func__, injpkt->debug_buf);
			
		}
			
		/* the ttl verification of a known status is scheduled with 2mins interval */
		ttlfocus.scheduleNextProbe2mins();
	}
}

/* return a sessiontrack given a packet; return a new sessiontrack if no one exist */
SessionTrack& TCPTrack::get_sessiontrack(const Packet &pkt)
{
	/* create map key */
	SessionTrackKey key = { pkt.ip->daddr, pkt.tcp->source, pkt.tcp->dest };
	/* try to insert a new elem, return an old one if already exists */
	SessionTrack &sessiontrack = sex_map.insert(pair<SessionTrackKey, SessionTrack>(key, pkt)).first->second;
	/* update access timestamp using global clock */
	sessiontrack.access_timestamp = clock.tv_sec;
	return sessiontrack;
}

/* return a ttlfocus given a packet; return a new ttlfocus if no one exist */
TTLFocus& TCPTrack::get_ttlfocus(const Packet &pkt)
{
	/* try to insert a new elem, return an old one if already exists */
	TTLFocus &ttlfocus = ttlfocus_map.insert(pair<const unsigned int, TTLFocus>(pkt.ip->daddr, pkt)).first->second;
	/* update access timestamp using global clock */
	ttlfocus.access_timestamp = clock.tv_sec;
	return ttlfocus;
}

/* cycles on sex_map and delete recors if expired */
void TCPTrack::manage_expired_sessiontracks()
{
	for(SessionTrackMap::iterator it = sex_map.begin(); it != sex_map.end();) {
		if((*it).second.access_timestamp + SESSIONTRACK_EXPIRETIME < clock.tv_sec)
			sex_map.erase(it++);
		else
			it++;
	}
}

/* cycles on ttlfocus_map and delete recors if expired */
void TCPTrack::manage_expired_ttlfocuses()
{
	for(TTLFocusMap::iterator it = ttlfocus_map.begin(); it != ttlfocus_map.end();) {
		if((*it).second.access_timestamp + TTLFOCUS_EXPIRETIME < clock.tv_sec)
			ttlfocus_map.erase(it++);
		else
			it++;
	}
}

/*
 * analyze an incoming icmp packet.
 * at the moment, the unique icmp packet analyzed is the  ICMP_TIME_EXCEEDED.
 * a TIME_EXCEEDED packet should contains informations to discern HOP distance
 * from a remote host.
*/
bool TCPTrack::analyze_incoming_icmp(Packet &pkt)
{
	if (pkt.icmp->type == ICMP_TIME_EXCEEDED)
		return true;

	const struct iphdr *badiph;
	const struct tcphdr *badtcph;

	badiph = (struct iphdr *)((unsigned char *)pkt.icmp + sizeof(struct icmphdr));
	badtcph = (struct tcphdr *)((unsigned char *)badiph + (badiph->ihl * 4));

	if (badiph->protocol == IPPROTO_TCP) {
		/* 
		 * Here We call the find() mathod of std::map because
		 * We want to test the ttl existance an NEVER NEVER NEVER create a new one
		 * to not permit an external packet to force us to activate a ttlbrouteforce session
		 */ 
		TTLFocusMap::iterator it = ttlfocus_map.find(badiph->daddr);
		if(it != ttlfocus_map.end()) {
			TTLFocus *ttlfocus = &(it->second);
			unsigned char expired_ttl = badiph->id - (ttlfocus->rand_key % 64);
			unsigned char exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

			if (ttlfocus->status != TTL_KNOWN && expired_ttl == exp_double_check) {
				ttlfocus->received_probe++;

				if (expired_ttl > ttlfocus->expiring_ttl) {
					ttlfocus->expiring_ttl = expired_ttl;
					snprintf(ttlfocus->debug_buf, sizeof(ttlfocus->debug_buf), "good TTL: recv %d", expired_ttl);
					ttlfocus->selflog(__func__, ttlfocus->debug_buf);
				}
				else  {
					snprintf(ttlfocus->debug_buf, sizeof(ttlfocus->debug_buf), "BAD TTL!: recv %d", expired_ttl);
					ttlfocus->selflog(__func__, ttlfocus->debug_buf);
				}
			}
			p_queue.remove(pkt);
			delete &pkt;
			return false;
		}
	}
	
	return true;
}

/*
 * analyze the ttl of an incoming tcp packet to discriminate a topology hop change
 */
void TCPTrack::analyze_incoming_tcp_ttl(Packet &pkt)
{
	/* 
	 * Here We call the find() mathod of std::map because
	 * We want to test the ttl existance an NEVER NEVER NEVER create a new one
	 * to not permit an external packet to force us to activate a ttlbrouteforce session
	 */	
	TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->saddr);
	if (it != ttlfocus_map.end()) {
		TTLFocus *ttlfocus = &(it->second);
		if(ttlfocus->status == TTL_KNOWN && ttlfocus->synack_ttl != pkt.ip->ttl) {
			/* probably a topology change has happened - we need a solution wtf!!  */
			snprintf(pkt.debug_buf, sizeof(pkt.debug_buf), 
				"probable net topology change! #probe %d [exp %d min work %d synack ttl %d]",
				ttlfocus->sent_probe, ttlfocus->expiring_ttl, 
				ttlfocus->min_working_ttl, ttlfocus->synack_ttl
			);
			pkt.selflog(__func__, pkt.debug_buf);
		}
	}
}

/*
 * this function was written when only the outgoing (client) connection was 
 * treat by sniffjoke, now also the server connections are trapped. the comments
 * and the variable referring to synack will not be exactly true in the 
 * server view. is only matter of naming anyway
 */
bool TCPTrack::analyze_incoming_tcp_synack(Packet &synack)
{
	TTLFocusMap::iterator it = ttlfocus_map.find(synack.ip->saddr);
	if (it != ttlfocus_map.end()) {
		TTLFocus *ttlfocus = &(it->second);

		snprintf(synack.debug_buf, sizeof(synack.debug_buf), "puppet %d Incoming SYN/ACK", ntohs(ttlfocus->puppet_port));
		synack.selflog(__func__, synack.debug_buf);

		if (synack.tcp->dest == ttlfocus->puppet_port) {
			unsigned char discern_ttl =  ntohl(synack.tcp->ack_seq) - ttlfocus->rand_key - 1;

			ttlfocus->received_probe++;
			ttlfocus->status = TTL_KNOWN;

			if (ttlfocus->min_working_ttl > discern_ttl && discern_ttl <= ttlfocus->sent_probe) { 
				ttlfocus->min_working_ttl = discern_ttl;
				ttlfocus->expiring_ttl = discern_ttl - 1;
				ttlfocus->synack_ttl = synack.ip->ttl;
			}

			snprintf(ttlfocus->debug_buf, sizeof(ttlfocus->debug_buf), "discerned TTL %d minworking %d expiring %d incoming value %d", 
				discern_ttl, ttlfocus->min_working_ttl, ttlfocus->expiring_ttl, ttlfocus->synack_ttl);
			ttlfocus->selflog(__func__, ttlfocus->debug_buf);

			p_queue.remove(synack);
			delete &synack;			
			return false;
		}

		/* 
		 * connect(3, {sa_family=AF_INET, sin_port=htons(80), 
		 * sin_addr=inet_addr("89.186.95.190")}, 16) = 
		 * -1 EHOSTUNREACH (No route to host)
		 *
		 * sadly, this happens when you try to use the real syn. for
		 * this reason I'm using encoding in random sequence and a
		 * fake source port (puppet port)
		 *
		 * anyway, every SYN/ACK received is passed to the hosts, so
		 * our kernel should RST/ACK the unrequested connect.
		 *
		 * this will appear as a problem by the remote server, because
		 * a ttlBRUTEFORCE related to a different port will be blocked 
		 * by the NAT, so our ttl tracking will be less effective. is
		 * possible too, make a passive os fingerprint of the client and
		 * suppose the default usage TTL (64). this work/research will be
		 * completed in the future.
		 */
	}
	
	return true;
}

bool TCPTrack::analyze_outgoing(Packet &pkt)
{
	SessionTrack &sessiontrack = get_sessiontrack(pkt);
	sessiontrack.packet_number++;
	
	TTLFocus &ttlfocus = get_ttlfocus(pkt);
	if (ttlfocus.status == TTL_BRUTEFORCE) {
		p_queue.remove(pkt);
		p_queue.insert(Q_KEEP, pkt);
		return false;
	}
	
	return true;
}

bool TCPTrack::analyze_keep(Packet &pkt) {
	if(pkt.source == TUNNEL && pkt.proto == TCP) {
		TTLFocus &ttlfocus = get_ttlfocus(pkt);
		if (ttlfocus.status == TTL_BRUTEFORCE)
			return false;
	}
	
	return true;
}

/* 
 * inject_hack_in_queue is one of the core function in sniffjoke:
 *
 * the hacks are, for the most, two kinds.
 *
 * one kind require the knowledge of exactly hop distance between the two end points, to forge
 * packets able to expire an hop before the destination IP addres, and inject in the
 * stream some valid TCP RSQ, TCP FIN and fake sequenced packet.
 *
 * the other kind of attack work forging packets with bad details, wishing the sniffer ignore
 * those irregularity and poison the connection tracking: injection of RST with bad checksum;
 * bad checksum FIN packet; bad checksum fake SEQ; valid reset with bad sequence number ...
 *
 */
void TCPTrack::inject_hack_in_queue(Packet &orig_pkt)
{
	SessionTrack &sessiontrack = get_sessiontrack(orig_pkt);

	vector<PluginTrack>::iterator it;
	PluginTrack *hppe;
	
	/* SELECT APPLICABLE HACKS */
	for (it = hack_pool.begin(); it != hack_pool.end(); it++) {
		hppe = &(*it);
		hppe->enabled = true;
		hppe->enabled &= hppe->selfObj->Condition(orig_pkt);
		hppe->enabled &= percentage(
					sessiontrack.packet_number,
					hppe->selfObj->hackFrequency,
					runconfig.portconf[ntohs(orig_pkt.tcp->dest)]
				);
	}

	/* -- RANDOMIZE HACKS APPLICATION */
	random_shuffle(hack_pool.begin(), hack_pool.end());

	/* -- FINALLY, SEND THE CHOOSEN PACKET(S) */
	for (it = hack_pool.begin(); it != hack_pool.end(); it++) 
	{
		/* must be moved in the do/while loop based on HackPacket->num_pkt_gen */
		vector<Packet*>::iterator hack_it;
		Packet *injpkt;

		hppe = &(*it);
		if(!hppe->enabled) 
			continue;

		hppe->selfObj->createHack(orig_pkt);
		
		for (hack_it = hppe->selfObj->pktVector.begin() ; hack_it < hppe->selfObj->pktVector.end(); hack_it++) {
		
			injpkt = *hack_it;

			/* we trust in the external developer, but is required a safety check by sniffjoke :) */
			if(!injpkt->selfIntegrityCheck(hppe->selfObj->hackName)) 
			{
				debug.log(ALL_LEVEL, "invalid packet generated by hack %s", hppe->selfObj->hackName);

				/* if you are running with --debug 6, I suppose you are the developing the plugins */
				if(runconfig.debug_level == PACKETS_DEBUG) 
					throw runtime_error("");

				/* otherwise, the error was reported and sniffjoke continue to work */
				delete injpkt;
				continue;
			}

			/* source and status are ignored in selfIntegrityCheck, evilbit is set here to be EVIL */
			injpkt->mark(LOCAL, EVIL);
			/* here we set the evilbit http://www.faqs.org/rfcs/rfc3514.html
			 * we are working in support RFC3514 and http://www.kill-9.it/rfc/draft-no-frills-tcp-04.txt too */

			snprintf(injpkt->debug_buf, sizeof(injpkt->debug_buf), "Injected from %s", hppe->selfObj->hackName);
			injpkt->selflog(__func__, injpkt->debug_buf);

			switch(injpkt->position) {
				case ANTICIPATION:
					p_queue.insert_before(*injpkt, orig_pkt);
					break;
				case POSTICIPATION:
					p_queue.insert_after(*injpkt, orig_pkt);
					break;
				case ANY_POSITION:
					if(random() % 2)
						p_queue.insert_before(*injpkt, orig_pkt);
					else
						p_queue.insert_after(*injpkt, orig_pkt);
					break;
				case POSITIONUNASSIGNED:
		                        debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
		                        SJ_RUNTIME_EXCEPTION("");
			}
		}
		hppe->selfObj->pktVector.clear();
		
		if(hppe->selfObj->removeOrigPkt == true) {
			p_queue.remove(orig_pkt);
			delete &orig_pkt;
		}
	}
}

/* 
 * Last_pkt_fix is the last modification applied to packets.
 * Modification involve only TCP packets coming from TUNNEL, thos 
 * packets are check if ->evilbit is set to be EVIL. those packets 
 * receive the sniffjoke modification aiming to be discarded, or
 * never reach, the remote host, and desyncing the sniffer.
 *
 * p.s. if you are reading this piece of code for fix your sniffer:
 *   WE SHALL BE YOUR NIGHTMARE.
 *   WE SHALL BE YOUR NIGHTMARE.
 *   WE SHALL BE YOUR NIGHTMARE, LOSE ANY HOPE, WE HAD THE RANDOMNESS IN OUR SIDE.
 *
 *
 * 
 *   PRESCRIPTION: will EXPIRE BEFORE REACHING destination (due to ttl modification)
 * 			could be: ONLY EVIL PACKETS
 *   GUILTY:       will BE DISCARDED by destination (due to some error introduction)
 *                      at the moment the only error applied is the invalidation tcp checksum
 *                      could be: ONLY EVIL PACKETS 
 *   MALFORMED:    will BE DISCARDED by destination due to misuse of ip options
 *   			could be: ONLY EVIL PACKETS
 *   INNOCENT:	   will BE ACCEPTED, so, INNOCENT but EVIL cause the same treatment of a
 *   			GOOD packet.
 *
 *   the non EVIL+INNOCENT and the GOOD packets will be sent with silly modification:
 *	- a non default TTL value, so to be more or less like the PRESCRIPTION pkts
 *	- some invalid TCP OPTIONS field
 *	- some weird but acceptable IP OPTIONS field
 */
bool TCPTrack::last_pkt_fix(Packet &pkt)
{
	if (pkt.proto != TCP || pkt.source == NETWORK) {
		return true;
	} else if (pkt.source == TTLBFORCE) {
		pkt.fixIpTcpSum();
		return true;
	}

	TTLFocus &ttlfocus = get_ttlfocus(pkt);
	
	/* 1nd check: what kind of hacks will be apply ? */
	if(pkt.wtf == RANDOMDAMAGE)
	{
		/* 
		 * If sniffjoke is running there is always a a tecnique enabled
		 * so here it's assured that we will assign an enabled tecnique.
		 * 
		 */
		
		if(ISSET_CHECKSUM(runconfig.scrambletech))
			pkt.wtf = GUILTY;
		else if(ISSET_TTL(runconfig.scrambletech))
			pkt.wtf = PRESCRIPTION;
		else if(ISSET_MALFORMED(runconfig.scrambletech))
			pkt.wtf = MALFORMED;

		if(ISSET_TTL(runconfig.scrambletech) && RANDOMPERCENT(45))
			pkt.wtf = PRESCRIPTION;

		if(ISSET_MALFORMED(runconfig.scrambletech) && RANDOMPERCENT(80)) 
			pkt.wtf = MALFORMED;
	}
	
	/* hack selection, second stage */
	switch(pkt.wtf) {
		case PRESCRIPTION:
			if (ISSET_TTL(runconfig.scrambletech))
				break;
			else
				return false;
		case MALFORMED:
			if (ISSET_MALFORMED(runconfig.scrambletech))
				break;
			else
				return false;
		case GUILTY:
			if (ISSET_CHECKSUM(runconfig.scrambletech))
				break;
			else
				return false;
		case INNOCENT:
			break;
		case RANDOMDAMAGE:
		case JUDGEUNASSIGNED:
		default:
			SJ_RUNTIME_EXCEPTION("");
			break;
	}

	if(ISSET_MALFORMED(runconfig.scrambletech)) {
		/* IP options, every packet subject if possible, and MALFORMED will be apply */
		if(pkt.wtf == MALFORMED) {	
			if(!(pkt.Inject_IPOPT(/* corrupt ? */ true, /* strip previous options */ true)))
				return false;
		} else {
			if (RANDOMPERCENT(20))
				pkt.Inject_IPOPT(/* corrupt ? */ false, /* strip previous options ? */ false);
		}

		// VERIFY - TCP doesn't cause a failure of the packet, the BAD TCPOPT will be used always
		if (RANDOMPERCENT(20)) {
			if RANDOMPERCENT(50)
				pkt.Inject_TCPOPT(/* corrupt ? */ false, /* stript previous ? */ true);
			else
				pkt.Inject_TCPOPT(/* corrupt ? */ true, /* stript previous ? */ true);		
		}
	}

	/* begin 2st check: WHAT VALUE OF TTL GIVE TO THE PACKET ? */	
	/* TTL modification - every packet subjected if possible */
	if (!(ttlfocus.status & (TTL_UNKNOWN | TTL_BRUTEFORCE))) {
		if (pkt.wtf == PRESCRIPTION) 
			pkt.ip->ttl = ttlfocus.expiring_ttl - (random() % 5);
		else
			pkt.ip->ttl = ttlfocus.min_working_ttl + (random() % 5);
	} else {
		pkt.ip->ttl = STARTING_ARB_TTL + (random() % 100);
	}
	/* end 2st check */
	
	/* fixing the mangled packet */
	pkt.fixIpTcpSum();

	/* corrupted checksum application if required */
	if (pkt.wtf == GUILTY)
		pkt.tcp->check ^= (0xd34d ^ (unsigned short)random());

	pkt.selflog(__func__, "Packet ready to be send");
	
	return true;
}

/* the packet is add in the packet queue for be analyzed in a second time */
void TCPTrack::writepacket(const source_t source, const unsigned char *buff, int nbyte)
{
	try {
		Packet *pkt = new Packet(buff, nbyte);
		pkt->mark(source, INNOCENT, GOOD);
	
		/* 
		* the packet from the tunnel are put with lower priority and the
		* hack-packet, injected from sniffjoke, are put in the higher one.
		* when the software loop for in p_queue.get(status, source, proto) the 
		* forged packet are sent before the originals one.
		*/
		
		p_queue.insert(Q_YOUNG, *pkt);
	
		return;
		
	} catch (exception &e) {
		/* malformed packet, ignored */
		return;
	}
}

Packet* TCPTrack::readpacket()
{
	Packet *pkt;

	p_queue.select(Q_PRIORITY_SEND);
	while ((pkt = p_queue.get()) != NULL) {
		p_queue.remove(*pkt);
		if(!last_pkt_fix(*pkt))
			delete pkt;
		else
			return pkt;
		
	}

	p_queue.select(Q_SEND);
	while ((pkt = p_queue.get()) != NULL) {
		p_queue.remove(*pkt);
		if(!last_pkt_fix(*pkt))
			delete pkt;
		else
			return pkt;
	}

	return NULL;
}



/* 
 *
 * This is an important and critical function for sniffjoke operativity.
 * 
 * analyze_packets_queue is called from the main.cc ppoll() block
 * 
* All the functions that are called here  inside a p_queue.get() cycle:
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
	/* if the queue is empy we have nothing to do */
	if(!p_queue.size())
		return;	

	Packet *pkt;
	bool send;

	/* update the internal clock */
	clock_gettime(CLOCK_REALTIME, &clock);
	
	/* manage expired sessions and ttlfocuses every APQ_MANAGMENT_ROUTINE_TIMER seconds */
	if(!(clock.tv_sec % APQ_MANAGMENT_ROUTINE_TIMER)) {
		manage_expired_sessiontracks();
		manage_expired_ttlfocuses();
	}
	
	/* 
	 * incoming TCP. sniffjoke algorithm open/close sessions and detect TTL
	 * lists analyzing SYN+ACK and FIN|RST packet
	 */
	p_queue.select(Q_YOUNG);
	while ((pkt = p_queue.get()) != NULL) {
		send = true;
		if(pkt->source == NETWORK) {
			if(pkt->proto == ICMP) {
				send = analyze_incoming_icmp(*pkt);
			} else  if(pkt->proto == TCP) {
				/* analysis of the incoming TCP packet for check if TTL we are receiving is
				* changed or not. is not the correct solution for detect network topology
				* change, but we need it! */
				analyze_incoming_tcp_ttl(*pkt);

				send = analyze_incoming_tcp_synack(*pkt);
			}
		} else if(pkt->source == TUNNEL) {
			if(pkt->proto == TCP) {
				/* check if hacks must be bypassed for this destination port */
				if (runconfig.portconf[ntohs(pkt->tcp->dest)] != NONE)
					send = analyze_outgoing(*pkt);
			}
		}
			
		if(send == true) {
			p_queue.remove(*pkt);
			p_queue.insert(Q_SEND, *pkt);
		}
	}

	p_queue.select(Q_KEEP);
	while ((pkt = p_queue.get()) != NULL) {
		send = analyze_keep(*pkt);
		if(send == true) {
			p_queue.remove(*pkt);
			p_queue.insert(Q_SEND, *pkt);
		}
	}

	p_queue.select(Q_SEND);	
	while ((pkt = p_queue.get()) != NULL) {
		if(pkt->proto == TCP && pkt->source == TUNNEL)
			inject_hack_in_queue(*pkt);
	}


	for (TTLFocusMap::iterator it = ttlfocus_map.begin(); it != ttlfocus_map.end(); it++) {
		if((*it).second.status & (TTL_BRUTEFORCE | TTL_KNOWN))
			inject_ttlprobe_in_queue((*it).second);
	}
}
