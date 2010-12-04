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

TCPTrack::TCPTrack(const sj_config &runcfg, HackPool &hpp) :
	runconfig(runcfg),
	hack_pool(hpp)
{
	debug.log(VERBOSE_LEVEL, __func__);	
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
			if(!((uint8_t)sj_clock.tv_sec % 5))
				freqret = 12;
			else
				freqret = 1;
			break;
		case TIMEBASED20S:
			if(!((uint8_t)sj_clock.tv_sec % 20))
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
	if((ttlfocus.access_timestamp < sj_clock.tv_sec - 30) || !isSchedulePassed(ttlfocus.next_probe_time))
		return;

	if (ttlfocus.sent_probe == runconfig.max_ttl_probe) {
		ttlfocus.status = TTL_UNKNOWN;
		ttlfocus.sent_probe = 0;
		ttlfocus.received_probe = 0;
		ttlfocus.ttl_estimate = 0xff;
		ttlfocus.synack_ttl = 0;
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
			p_queue.insert(*injpkt, PRIORITY_SEND);
				
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
			while(pkts--) {
				++ttlfocus.sent_probe;
				injpkt = new Packet(ttlfocus.probe_dummy);
				injpkt->mark(TTLBFORCE, INNOCENT, GOOD);
				injpkt->ip->id = (ttlfocus.rand_key % 64) + ttl;
				injpkt->ip->ttl = ttl;
				injpkt->tcp->source = ttlfocus.puppet_port;
				injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttl);
				p_queue.insert(*injpkt, PRIORITY_SEND);
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

/* return a sessiontrack given a packet; return a new sessiontrack if no one exist */
SessionTrack& TCPTrack::get_sessiontrack(const Packet &pkt)
{
	SessionTrack *sessiontrack;
	
	/* create map key */
	const SessionTrackKey key = { pkt.ip->daddr, pkt.tcp->source, pkt.tcp->dest };
	
	/* check if the key it's already present */
	SessionTrackMap::iterator it = sex_map.find(key);
	if(it != sex_map.end()) /* on hit: return the sessiontrack object. */
		sessiontrack = it->second;
	else { /* on miss: create a new sessiontrack and insert it into the map */
		SessionTrack * const newsession = new SessionTrack(pkt);
		sessiontrack = sex_map.insert(pair<const SessionTrackKey, SessionTrack*>(key, newsession)).first->second;
	}
		
	/* update access timestamp using global clock */
	sessiontrack->access_timestamp = sj_clock.tv_sec;

	return *sessiontrack;
}

/* return a ttlfocus given a packet; return a new ttlfocus if no one exist */
TTLFocus& TCPTrack::get_ttlfocus(const Packet &pkt)
{
	TTLFocus *ttlfocus;
	
	/* check if the key it's already present */
	TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->daddr);
	if(it != ttlfocus_map.end()) /* on hit: return the ttlfocus object. */
		ttlfocus = it->second;
	else { /* on miss: create a new ttlfocus and insert it into the map */
		TTLFocus * const newttlfocus = new TTLFocus(pkt);
		ttlfocus = ttlfocus_map.insert(pair<const uint32_t, TTLFocus*>(pkt.ip->daddr, newttlfocus)).first->second;
	}
	
	/* update access timestamp using global clock */
	ttlfocus->access_timestamp = sj_clock.tv_sec;
	return *ttlfocus;
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
		if(it != ttlfocus_map.end()) {
			TTLFocus *ttlfocus = it->second;
			const uint8_t expired_ttl = badiph->id - (ttlfocus->rand_key % 64);
			const uint8_t exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

			if (ttlfocus->status != TTL_KNOWN && expired_ttl == exp_double_check) {
				
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
		if(ttlfocus->status == TTL_KNOWN && ttlfocus->synack_ttl != pkt.ip->ttl) {
			/* probably a topology change has happened - we need a solution wtf!!  */
			snprintf(pkt.debug_buf, sizeof(pkt.debug_buf), 
				"probable net topology change! #probe %u [ttl_estimate %u synack ttl %u]",
				ttlfocus->sent_probe, ttlfocus->ttl_estimate, ttlfocus->synack_ttl
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

			if (ttlfocus->status == TTL_UNKNOWN || discern_ttl < ttlfocus->ttl_estimate) { 
				ttlfocus->ttl_estimate = discern_ttl;
				ttlfocus->synack_ttl = pkt.ip->ttl;
			}
			
			ttlfocus->status = TTL_KNOWN;

			snprintf(ttlfocus->debug_buf, sizeof(ttlfocus->debug_buf), "discerned TTL %u ttl_estimate %u incoming value %u", 
				discern_ttl, ttlfocus->ttl_estimate, ttlfocus->synack_ttl);
			ttlfocus->selflog(__func__, ttlfocus->debug_buf);

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
	SessionTrack &sessiontrack = get_sessiontrack(pkt);
	++sessiontrack.packet_number;
	
	const TTLFocus &ttlfocus = get_ttlfocus(pkt);
	if (ttlfocus.status == TTL_BRUTEFORCE) {
		p_queue.insert(pkt, KEEP);
		return false;
	}
	
	return true;
}

bool TCPTrack::analyze_keep(Packet &pkt) {
	if(pkt.source == TUNNEL) {
		const TTLFocus &ttlfocus = get_ttlfocus(pkt);
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
	const SessionTrack &sessiontrack = get_sessiontrack(orig_pkt);

	vector<PluginTrack *> applicable_hacks;

	/* SELECT APPLICABLE HACKS */
	for (vector<PluginTrack*>::iterator it = hack_pool.begin(); it != hack_pool.end(); ++it) {
		PluginTrack *hppe = *it;
		bool applicable = true;
		applicable &= hppe->selfObj->Condition(orig_pkt);
		applicable &= percentage(
					sessiontrack.packet_number,
					hppe->selfObj->hackFrequency,
					runconfig.portconf[ntohs(orig_pkt.tcp->dest)]
				);
		if(applicable)
			applicable_hacks.push_back(hppe);
	}

	/* -- RANDOMIZE HACKS APPLICATION */
	random_shuffle(applicable_hacks.begin(), applicable_hacks.end());

	/* -- FINALLY, SEND THE CHOOSEN PACKET(S) */
	for (vector<PluginTrack *>::iterator it = applicable_hacks.begin(); it != applicable_hacks.end(); ++it) 
	{
		PluginTrack *hppe = *it;

		hppe->selfObj->createHack(orig_pkt);
		
		for (vector<Packet*>::iterator hack_it = hppe->selfObj->pktVector.begin(); hack_it < hppe->selfObj->pktVector.end(); ++hack_it) {
			Packet &injpkt = **hack_it;

			/*
			 * we trust in the external developer, but is required a safety check by sniffjoke :)
			 * source and status are ignored in selfIntegrityCheck.
			 */
			if(!injpkt.selfIntegrityCheck(hppe->selfObj->hackName)) 
			{
				debug.log(ALL_LEVEL, "invalid packet generated by hack %s", hppe->selfObj->hackName);

				/* if you are running with --debug 6, I suppose you are the developing the plugins */
				if(runconfig.debug_level == PACKETS_DEBUG) 
					SJ_RUNTIME_EXCEPTION("");

				/* otherwise, the error was reported and sniffjoke continue to work */
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
					p_queue.insert_before(injpkt, orig_pkt);
					break;
				case POSTICIPATION:
					p_queue.insert_after(injpkt, orig_pkt);
					break;
				case ANY_POSITION:
					if(random() % 2)
						p_queue.insert_before(injpkt, orig_pkt);
					else
						p_queue.insert_after(injpkt, orig_pkt);
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
	if (pkt.source == NETWORK || pkt.proto != TCP) {
		/* NETWORK packet and !TCP packets can be send without modification */
		return true;
	} else if (pkt.source == TTLBFORCE) {
		/* TTL probe packets need only the checksum to be fixed (IP + TCP)*/
		pkt.fixIpTcpSum();
		return true;
	}
	
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
			break;
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
	const TTLFocus &ttlfocus = get_ttlfocus(pkt);
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
void TCPTrack::writepacket(const source_t source, const unsigned char *buff, int nbyte)
{
	try {
		Packet* const pkt = new Packet(buff, nbyte);
		pkt->mark(source, INNOCENT, GOOD);
	
		/* 
		* the packet from the tunnel are put with lower priority and the
		* hack-packet, injected from sniffjoke, are put in the higher one.
		* when the software loop for in p_queue.get(status, source, proto) the 
		* forged packet are sent before the originals one.
		*/
		
		p_queue.insert(*pkt, YOUNG);
	
		return;
		
	} catch (exception &e) {
		/* malformed packet, ignored */
		return;
	}
}

/* 
 * this functions return a packet from queues PRIORITY_SEND and SEND
 * before return the packet the last_pkt_function is called,
 * and if that function decretee packet drop, packet it's dropped.
 * This is possibile for example for hack packet thtat for some reasons
 * fails in application.
 */
Packet* TCPTrack::readpacket()
{
	Packet *pkt;
	p_queue.select(PRIORITY_SEND);
	while ((pkt = p_queue.get()) != NULL) {
		p_queue.remove(*pkt);
		if(!last_pkt_fix(*pkt))
			delete pkt;
		else
			return pkt;
		
	}

	p_queue.select(SEND);
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
	/* manage expired sessions and ttlfocuses every APQ_MANAGMENT_ROUTINE_TIMER seconds */
	if(!(sj_clock.tv_sec % APQ_MANAGMENT_ROUTINE_TIMER)) {
		sex_map.manage_expired();
		ttlfocus_map.manage_expired();
	}
	
	/* if all queues are empy we have nothing to do */
	if(!p_queue.size())
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
		} else /* pkt->source == TUNNEL */ {
			if(pkt->proto == TCP) {
				/* check if hacks must be bypassed for this destination port */
				if (runconfig.portconf[ntohs(pkt->tcp->dest)] != NONE)
					send = analyze_outgoing(*pkt);
			}
		}
			
		if(send == true)
			p_queue.insert(*pkt, SEND);
	}

	/* we analyze every packet in KEEP queue to see if some can now be inserted in SEND queue */
	p_queue.select(KEEP);
	while ((pkt = p_queue.get()) != NULL) {
		bool send = analyze_keep(*pkt);
		if(send == true)
			p_queue.insert(*pkt, SEND);
	}

	/* for every packet in SEND queue we insert some random hacks */
	p_queue.select(SEND);	
	while ((pkt = p_queue.get()) != NULL) {
		if(pkt->proto == TCP && pkt->source == TUNNEL)
			inject_hack_in_queue(*pkt);
	}

bypass_queue_analysis:

	/* we need to verify the need of ttl probes for cached ttlfocus with status BRUTEFORCE and KNOWN*/
	for (TTLFocusMap::iterator it = ttlfocus_map.begin(); it != ttlfocus_map.end(); ++it) {
		if((*it).second->status == TTL_BRUTEFORCE || (*it).second->status == TTL_KNOWN) {
			inject_ttlprobe_in_queue(*(*it).second);
		}
	}
}
