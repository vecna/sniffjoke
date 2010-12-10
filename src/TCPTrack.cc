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
	debug.log(VERBOSE_LEVEL, __func__);	
}

TCPTrack::~TCPTrack(void) 
{
	debug.log(VERBOSE_LEVEL, __func__);
}

/*  
 *  this function is used from the sniffjoke routing for decretee the possibility for
 *  an hack to happen.
 *  the calculation involves:
 *   - the session packet_number, because for example hacks must happen, for the most,
 *     at the start of the session (between the first 10 packets),
 *   - a specified frequency selector provided by hacks programmer.
 *   - a port strengh selector (none|light|normal|heavy) defined in running configuration
 */
bool TCPTrack::percentage(uint32_t packet_number, Frequency freqkind, Strength weightness)
{
	uint8_t this_percentage = 0, freqret = 0;
	switch(freqkind) {
		case RARE:
			freqret = 3;
			break;
		case COMMON:
			freqret = 7;
			break;
		case ALWAYS:
			freqret = 25;
			break;
		case PACKETS10PEEK:
			if (!(++packet_number % 10) || !(--packet_number % 10) || !(--packet_number % 10))
				freqret = 10;
			else
				freqret = 1;
			break;
		case PACKETS30PEEK:
			if (!(++packet_number % 30) || !(--packet_number % 30) || !(--packet_number % 30))
				freqret = 10;
			else
				freqret = 1;
			break;
		case TIMEBASED5S:
			if (!((uint8_t)sj_clock.tv_sec % 5))
				freqret = 12;
			else
				freqret = 1;
			break;
		case TIMEBASED20S:
			if (!((uint8_t)sj_clock.tv_sec % 20))
				freqret = 12;
			else
				freqret = 1;
			break;
		case STARTPEEK:
			if (packet_number < 20)
				freqret = 10;
			else if (packet_number < 40)
				freqret = 5;
			else
				freqret = 1;
			break;
		case LONGPEEK:
			if (packet_number < 60)
				freqret = 8;
			else if (packet_number < 120)
				freqret = 4;
			else
				freqret = 1;
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

	return (((uint8_t)(random() % 100) + 1 <= this_percentage));
}

Frequency TCPTrack::betterProtocolFrequency(uint16_t dport, Frequency hackDefault) 
{
	uint32_t i;
	uint16_t hshort = ntohs(dport);
	/* need adding and/or a specific file instead and hardcoded struct */
	struct FrequencyMap Fm[] = 
	{
		{ 22, RARE },
		{ 23, COMMON },
		{ 25, ALWAYS },
		{ 80, STARTPEEK },
		{ 8080, STARTPEEK},
		{ 6667, ALWAYS}
	};

	for(i =0; i < sizeof(Fm); i++) 
	{
		if(Fm[i].port == hshort)
			return Fm[i].preferred;
	}

	return hackDefault;
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
	if (ttlfocus.sent_probe == runconfig.max_ttl_probe) {
		ttlfocus.status = TTL_UNKNOWN;
		ttlfocus.sent_probe = 0;
		ttlfocus.received_probe = 0;
		ttlfocus.ttl_estimate = 0xff;
		ttlfocus.ttl_synack = 0;
		/* retry scheduled in 10 minutes */
		updateSchedule(ttlfocus.next_probe_time, 600, 0);
		return;
	}
	
	Packet *injpkt;

	switch(ttlfocus.status) {
		case TTL_UNKNOWN:
			ttlfocus.status = TTL_BRUTEFORCE;
			/* do not break, continue inside TTL_BRUTEFORCE */
		case TTL_BRUTEFORCE:
			++ttlfocus.sent_probe;
			injpkt = new Packet(ttlfocus.probe_dummy);
			injpkt->mark(TTLBFORCE, INNOCENT, GOOD);
			injpkt->ip->id = (ttlfocus.rand_key % 64) + ttlfocus.sent_probe;
			injpkt->ip->ttl = ttlfocus.sent_probe;
			injpkt->tcp->source = ttlfocus.puppet_port;
			injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttlfocus.sent_probe);
			
			injpkt->fixIpTcpSum();
			p_queue.insert(*injpkt, SEND);
				
			snprintf(injpkt->debug_buf, sizeof(injpkt->debug_buf), "Injecting probe %u [ttl_estimate %u]",
				ttlfocus.sent_probe, ttlfocus.ttl_estimate
			);
			
			injpkt->selflog(__func__, injpkt->debug_buf);
			
			/* the bruteforce is scheduled with 50ms interval */
			updateSchedule(ttlfocus.next_probe_time, 0, 50000000);
			break;
		case TTL_KNOWN:
			ttlfocus.selectPuppetPort();
		
			ttlfocus.sent_probe = 0;
			ttlfocus.received_probe = 0;
			
			uint8_t pkts = 5;
			uint8_t ttl = ttlfocus.ttl_estimate > 5 ? ttlfocus.ttl_estimate - 5 : 0;
			while (pkts--) {
				++ttlfocus.sent_probe;
				injpkt = new Packet(ttlfocus.probe_dummy);
				injpkt->mark(TTLBFORCE, INNOCENT, GOOD);
				injpkt->ip->id = (ttlfocus.rand_key % 64) + ttl;
				injpkt->ip->ttl = ttl;
				injpkt->tcp->source = ttlfocus.puppet_port;
				injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttl);

				injpkt->fixIpTcpSum();
				p_queue.insert(*injpkt, SEND);

				ttl++;
					
				snprintf(injpkt->debug_buf, sizeof(injpkt->debug_buf), "Injecting probe %u [ttl_estimate %u]",
					ttlfocus.sent_probe, ttlfocus.ttl_estimate
				);
					
				injpkt->selflog(__func__, injpkt->debug_buf);
				
			}
				
			/* the ttl verification of a known status is scheduled with 2mins interval */
			updateSchedule(ttlfocus.next_probe_time, 120, 0);
			break;
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
	if (pkt.icmp->type != ICMP_TIME_EXCEEDED)
		return true;

	const struct iphdr * const badiph = (struct iphdr *)((unsigned char *)pkt.icmp + sizeof(struct icmphdr));
	const struct tcphdr * const badtcph = (struct tcphdr *)((unsigned char *)badiph + (badiph->ihl * 4));

	if (badiph->protocol == IPPROTO_TCP) {
		/* 
		 * Here we call the find() mathod of std::map because
		 * we want to test the ttl existence and NEVER NEVER NEVER create a new one
		 * to not permit an external packet to force us to activate a ttlbrouteforce session
		 */ 
		TTLFocusMap::iterator it = ttlfocus_map.find(badiph->daddr);
		if (it != ttlfocus_map.end()) {
			TTLFocus *ttlfocus = it->second;
			const uint8_t expired_ttl = badiph->id - (ttlfocus->rand_key % 64);
			const uint8_t exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

			if (expired_ttl == exp_double_check) {
				
				snprintf(pkt.debug_buf, sizeof(pkt.debug_buf), "puppet %d Incoming ICMP EXPIRED", ntohs(ttlfocus->puppet_port));
				pkt.selflog(__func__, pkt.debug_buf);
				
				++ttlfocus->received_probe;

				if (expired_ttl >= ttlfocus->ttl_estimate) {
					/*
					 * If we are changing our estimation due to an expired
					 * we have to set status = TTL_UNKNOWN
					 * this is particolar important to permit recalibration.
					 */ 
					ttlfocus->status = TTL_UNKNOWN;
					ttlfocus->ttl_estimate = expired_ttl + 1;
				}

				ttlfocus->selflog(__func__, NULL);

				/* the expired icmp scattered due to our ttl probes so we can trasparently remove it */
				p_queue.remove(pkt);
				delete &pkt;
				return false;
			}
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
	 * Here we call the find() mathod of std::map because
	 * we want to test the ttl existence and NEVER NEVER NEVER create a new one
	 * to not permit an external packet to force us to activate a ttlbrouteforce session
	 */ 
	TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->saddr);
	if (it != ttlfocus_map.end()) {
		TTLFocus *ttlfocus = it->second;
		if (ttlfocus->status == TTL_KNOWN && ttlfocus->ttl_synack != pkt.ip->ttl) {
			/* probably a topology change has happened - we need a solution wtf!!  */
			snprintf(pkt.debug_buf, sizeof(pkt.debug_buf), 
				"probable net topology change! #probe %u [ttl_estimate %u synack ttl %u]",
				ttlfocus->sent_probe, ttlfocus->ttl_estimate, ttlfocus->ttl_synack
			);
			pkt.selflog(__func__, pkt.debug_buf);
		}
	}
}

/*
 * this function analyzes the a tcp syn+ack;
 * Due to the ttlbruteforce stage a syn + ack will scatter for ttl >= expiring, so if the received packet
 * matches the puppet port used for the current ttlbruteforce session we can discern the ttl as:
 *     
 *     unsigned char discern_ttl =  ntohl(pkt.tcp->ack_seq) - ttlfocus->rand_key - 1;
 */
bool TCPTrack::analyze_incoming_tcp_synack(Packet &pkt)
{
	/* 
	 * Here we call the find() mathod of std::map because
	 * we want to test the ttl existence and NEVER NEVER NEVER create a new one
	 * to not permit an external packet to force us to activate a ttlbrouteforce session
	 */ 

	TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->saddr);
	if (it != ttlfocus_map.end()) {
		TTLFocus* const ttlfocus = it->second;
		
		if (pkt.tcp->dest == ttlfocus->puppet_port) {
			snprintf(pkt.debug_buf, sizeof(pkt.debug_buf), "puppet %d Incoming SYN/ACK", ntohs(ttlfocus->puppet_port));
			pkt.selflog(__func__, pkt.debug_buf);

			uint8_t discern_ttl =  ntohl(pkt.tcp->ack_seq) - ttlfocus->rand_key - 1;

			++ttlfocus->received_probe;

			if (discern_ttl < ttlfocus->ttl_estimate) { 
				ttlfocus->ttl_estimate = discern_ttl;
				ttlfocus->ttl_synack = pkt.ip->ttl;
			}
			
			ttlfocus->status = TTL_KNOWN;

			ttlfocus->selflog(__func__, NULL);

			/* the syn+ack scattered due to our ttl probes so we can trasparently remove it */
			p_queue.remove(pkt);
			delete &pkt;			
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
	SessionTrack &sessiontrack = sessiontrack_map.getSessionTrack(pkt);
	++sessiontrack.packet_number;
	
	const TTLFocus &ttlfocus = ttlfocus_map.getTTLFocus(pkt);
	if (ttlfocus.status == TTL_BRUTEFORCE) {
		p_queue.remove(pkt);
		p_queue.insert(pkt, KEEP);
		return false;
	}
	
	return true;
}

bool TCPTrack::analyze_keep(Packet &pkt) {
	if (pkt.source == TUNNEL) {
		const TTLFocus &ttlfocus = ttlfocus_map.getTTLFocus(pkt);
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
void TCPTrack::inject_hack_in_queue(Packet &origpkt)
{
	const SessionTrack &sessiontrack = sessiontrack_map.getSessionTrack(origpkt);

	vector<PluginTrack *> applicable_hacks;

	/* SELECT APPLICABLE HACKS */
	for (vector<PluginTrack*>::iterator it = hack_pool.begin(); it != hack_pool.end(); ++it) {
		PluginTrack *hppe = *it;
		bool applicable = true;
		applicable &= hppe->selfObj->Condition(origpkt);
		applicable &= percentage(
					sessiontrack.packet_number,
					betterProtocolFrequency(sessiontrack.dport, hppe->selfObj->hackFrequency),
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

		hppe->selfObj->createHack(origpkt);
		
		for (vector<Packet*>::iterator hack_it = hppe->selfObj->pktVector.begin(); hack_it < hppe->selfObj->pktVector.end(); ++hack_it) {
			Packet &injpkt = **hack_it;

			/*
			 * we trust in the external developer, but is required a safety check by sniffjoke :)
			 * source and status are ignored in selfIntegrityCheck.
			 */
			if (!injpkt.selfIntegrityCheck(hppe->selfObj->hackName)) 
			{
				debug.log(ALL_LEVEL, "invalid packet generated by hack %s", hppe->selfObj->hackName);

				/* if you are running with --debug 6, I suppose you are the developing the plugins */
				if (runconfig.debug_level == PACKETS_DEBUG) 
					SJ_RUNTIME_EXCEPTION("");

				/* otherwise, the error was reported and sniffjoke continue to work */
				delete &injpkt;
				continue;
			}
			
			if(!last_pkt_fix(injpkt)) {
				delete &injpkt;
				continue;
			}
			
			/* here we set the evilbit http://www.faqs.org/rfcs/rfc3514.html
			 * we are working in support RFC3514 and http://www.kill-9.it/rfc/draft-no-frills-tcp-04.txt too */
			injpkt.mark(LOCAL, EVIL);

			snprintf(injpkt.debug_buf, sizeof(injpkt.debug_buf), "Injected from %s", hppe->selfObj->hackName);
			injpkt.selflog(__func__, injpkt.debug_buf);

			switch(injpkt.position) {
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
		                        debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
		                        SJ_RUNTIME_EXCEPTION("");
			}
		}

		hppe->selfObj->pktVector.clear();
		
		if (hppe->selfObj->removeOrigPkt == true) {
			p_queue.remove(origpkt);
			delete &origpkt;
		}
	}
}

/* 
 * Last_pkt_fix is the last modification applied to packets.
 * Modification involve only TCP packets coming from TUNNEL, those 
 * packets are checked in evilbit; if it's set to be EVIL. those packets 
 * receive the sniffjoke modification aiming to be discarded, or
 * never reach, the remote host, and desyncing the sniffer.
 *
 * p.s. if you are reading this piece of code for fix your sniffer:
 *   we SHALL BE YOUR NIGHTMARE.
 *   we SHALL BE YOUR NIGHTMARE.
 *   we SHALL BE YOUR NIGHTMARE, LOSE ANY HOPE, we HAD THE RANDOMNESS IN OUR SIDE.
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
	/*
	 * 1nd check: what kind of hacks will be apply ?
	 * here we verify if that the random selected hacks are really
	 * applicable in reference to configuration provided.
	 */
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
			/* 
			 * here we handle the specific case RANDOMDAMAGE.
			 * If sniffjoke is running there is always a tecnique enabled;
			 * so here it's assured that here we will select an enabled tecnique.
			 */
			
			if (ISSET_CHECKSUM(runconfig.scrambletech))
				pkt.wtf = GUILTY;
			else if (ISSET_TTL(runconfig.scrambletech))
				pkt.wtf = PRESCRIPTION;
			else if (ISSET_MALFORMED(runconfig.scrambletech))
				pkt.wtf = MALFORMED;

			if (ISSET_TTL(runconfig.scrambletech) && RANDOMPERCENT(45))
				pkt.wtf = PRESCRIPTION;

			if (ISSET_MALFORMED(runconfig.scrambletech) && RANDOMPERCENT(80)) 
				pkt.wtf = MALFORMED;
			break;
		case JUDGEUNASSIGNED:
		default:
			SJ_RUNTIME_EXCEPTION("");
			break;
	}

	if (ISSET_MALFORMED(runconfig.scrambletech)) {
		/* IP options, every packet subject if possible, and MALFORMED will be apply */
		if (pkt.wtf == MALFORMED) {	
			if (!(pkt.Inject_IPOPT(/* corrupt ? */ true, /* strip previous options */ true)))
				return false;
		} else {
			if (RANDOMPERCENT(20))
				pkt.Inject_IPOPT(/* corrupt ? */ false, /* strip previous options ? */ false);
		}

		/* At the time we are not apart of TCP options that lead destination to drop the packet,
		 * so for the moment no tcp options are injection.
		if (RANDOMPERCENT(20)) {
			if RANDOMPERCENT(50)
				pkt.Inject_TCPOPT(/ * corrupt ? * / false, / * stript previous ? * / true);
			else
				pkt.Inject_TCPOPT(/ * corrupt ? * / true, / * stript previous ? * / true);		
		}
		*/
	}

	/* begin 2st check: WHAT VALUE OF TTL GIVE TO THE PACKET ? */	
	/* TTL modification - every packet subjected if possible */
	const TTLFocus &ttlfocus = ttlfocus_map.getTTLFocus(pkt);
	if (!(ttlfocus.status & (TTL_UNKNOWN | TTL_BRUTEFORCE))) {
		/*
		 * here we use the ttl_estimate value to set the ttl in the packet;
		 * at the time, we does use the precise estimate for testing our infrastructure, but probably
		 * in real applications we will need a safe margin 1 or 2 hops.
		 */
		if (pkt.wtf == PRESCRIPTION) 
			pkt.ip->ttl = ttlfocus.ttl_estimate - (random() % 4) - 1;	/* [-1, -5], 5 values */
		else
			pkt.ip->ttl = ttlfocus.ttl_estimate + (random() % 4); 		/* [+0, +4], 5 values */
	} else {
		pkt.ip->ttl = STARTING_ARB_TTL + (random() % 100);
	}
	/* end 2st check */
	
	/* fixing the mangled packet */
	pkt.fixIpTcpSum();

	/* corrupted checksum application if required */
	if (pkt.wtf == GUILTY)
		pkt.tcp->check += 0xd34d;

	pkt.selflog(__func__, "Packet ready to be send");
	
	return true;
}

/* the packet is add in the packet queue for be analyzed in a second time */
void TCPTrack::writepacket(source_t source, const unsigned char *buff, int nbyte)
{
	try {
		Packet* const pkt = new Packet(buff, nbyte);
		pkt->mark(source, INNOCENT, GOOD);
	
		p_queue.insert(*pkt, YOUNG);	
		
	} catch (exception &e) {
		/* anomalous/malformed packets are flushed bypassing the queue */
		debug.log(ALL_LEVEL, "malformed original packet dropped: %s", e.what());
	}
}

/* 
 * this functions return a packet a packet given a specific source from SEND queue
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
	while ((pkt = p_queue.get()) != NULL) {
		if (pkt->source & mask) {
			p_queue.remove(*pkt);
			return pkt;
		}
		
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
deadline TCPTrack::analyze_packets_queue()
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
	while ((pkt = p_queue.get()) != NULL) {
		bool send = true;
		if (pkt->source == NETWORK) {
			if (pkt->proto == ICMP) {
				send = analyze_incoming_icmp(*pkt);
			} else  if (pkt->proto == TCP) {
				/* analysis of the incoming TCP packet for check if TTL we are receiving is
				* changed or not. is not the correct solution for detect network topology
				* change, but we need it! */
				analyze_incoming_tcp_ttl(*pkt);

				send = analyze_incoming_tcp_synack(*pkt);
			}
		} else /* pkt->source == TUNNEL */ {
			if (pkt->proto == TCP) {
				/* check if hacks must be bypassed for this destination port */
				if (runconfig.portconf[ntohs(pkt->tcp->dest)] != NONE)
					send = analyze_outgoing(*pkt);
			}
		}
			
		if (send == true) {
			p_queue.remove(*pkt);
			if(pkt->source == NETWORK || pkt->proto != TCP || last_pkt_fix(*pkt))
				p_queue.insert(*pkt, SEND);
			else
				SJ_RUNTIME_EXCEPTION("");
		}
	}

	/* we analyze every packet in KEEP queue to see if some can now be inserted in SEND queue */
	p_queue.select(KEEP);
	while ((pkt = p_queue.get()) != NULL) {
		bool send = analyze_keep(*pkt);
		if (send == true) {
			p_queue.remove(*pkt);
			if(last_pkt_fix(*pkt))
				p_queue.insert(*pkt, SEND);
			else
				SJ_RUNTIME_EXCEPTION("");
		}
	}

	/* for every packet in SEND queue we insert some random hacks */
	p_queue.select(SEND);	
	while ((pkt = p_queue.get()) != NULL) {
		if (pkt->source == TUNNEL && pkt->proto == TCP)
			inject_hack_in_queue(*pkt);
	}

bypass_queue_analysis:


	/*
	 * Call sessiontrack_map and ttlfocus_map manage routine.
	 * It's fundamental to do this here, after SEND packet fix and before
	 * forging ttl probes.
	 * In fact the two routine in case that their respective memory threshold
	 * limits are passed will delete the oldest records.
	 * This is completely safe because send packets are just fixed and there
	 * is no problem if we does not schedule a ttlprobe for a cycle.
	 * KEEP packets will scatter a new ttlfocus at the next cycle.
	 */

	sessiontrack_map.manage();
	ttlfocus_map.manage();

	/* 
	 * here we verify the need of ttl probes for cached ttlfocus with status BRUTEFORCE and KNOWN
	 * doing this there is an optimization we can do: we can keep the closest schedule and
	 * we can return it to the caller.
	 * in fact with no incoming packets there is no need to call the analyze_packet_queue until
	 * the next closest schedule.
	 */
	deadline min_schedule;
	
	for (TTLFocusMap::iterator it = ttlfocus_map.begin(); it != ttlfocus_map.end(); ++it) {
		TTLFocus &ttlfocus = *((*it).second);
		if (ttlfocus.status & (TTL_BRUTEFORCE | TTL_KNOWN)) {
			if ((ttlfocus.access_timestamp > sj_clock.tv_sec - 30) && isSchedulePassed(ttlfocus.next_probe_time))
				inject_ttlprobe_in_queue(*(*it).second);

			if (min_schedule.valid == false)
				if(ttlfocus.next_probe_time.tv_sec < min_schedule.timeline.tv_sec
				|| ttlfocus.next_probe_time.tv_nsec < min_schedule.timeline.tv_nsec) 
			{
				min_schedule.valid = true;
				min_schedule.timeline = ttlfocus.next_probe_time;
			}
		}	
	}
	
	return min_schedule;
}
