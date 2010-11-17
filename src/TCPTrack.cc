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

TCPTrack::TCPTrack(sj_config& runcfg, HackPool& hpp) :
	runconfig(runcfg),
	youngpacketspresent(false),
	/* fail is the public member used to signal a failure in plugin's loading, 
	 * hack_pool is a "class HackPacketPool", that extend a vector of HackPacketPoolElem */
	hack_pool(hpp)
{
	debug.log(VERBOSE_LEVEL, __func__);
	
	/* random pool initialization */
	for (int i = 0; i < ((random() % 40) + 3); i++) 
		srandom((unsigned int)time(NULL) ^ random());
}

TCPTrack::~TCPTrack(void) 
{
	debug.log(VERBOSE_LEVEL, __func__);
	ttlfocus_map.dump();
}

/*  
 *  the variable is used from the sniffjoke routing for decreete the possibility of
 *  an hack happens. this variable are mixed in probabiliy with the session->packet_number, because
 *  the hacks must happens, for the most, in the start of the session (the first 10 packets),
 *  other hacks injection should happen during the session. Those value are mixed with thr
 *  selecter port Strengh (none|light|normal|heavy) and the Hack frequency,
 *  better explanation about this algorithm in http://www.delirandom.net/sniffjoke/plugin
 */
bool TCPTrack::percentage(unsigned int packet_number, Frequency freqkind, Strength weightness)
{
	unsigned int this_percentage = 0, freqret = 0;
	time_t now;
	switch(freqkind) {
		case RARE:
			freqret = 3;
			break;
		case COMMON:
			freqret = 7;
			break;
		case PACKETS10PEEK:
			if( !(++packet_number % 10) || !(--packet_number % 10) || !(--packet_number % 10) )
				freqret = 10;
			else
				freqret = 1;
			break;
		case PACKETS30PEEK:
			if( !(++packet_number % 30) || !(--packet_number % 30) || !(--packet_number % 30) )
				freqret = 10;
			else
				freqret = 1;
			break;
		case TIMEBASED5S:
			now = time(NULL);
			if( !((unsigned int)now % 5) )
				freqret = 12;
			else
				freqret = 1;
			break;
		case TIMEBASED20S:
			now = time(NULL);
			if( !((unsigned int)now % 20) )
				freqret = 12;
			else
				freqret = 1;
			break;
		case STARTPEEK:
			if( packet_number < 20)
				freqret = 10;
			else if ( packet_number < 40)
				freqret = 5;
			else
				freqret = 1;
			break;
		case LONGPEEK:
			if( packet_number < 60)
				freqret = 8;
			else if ( packet_number < 120)
				freqret = 4;
			else
				freqret = 1;
			break;
		case FREQUENCYUNASSIGNED:
                        debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
                        SJ_RUNTIME_EXCEPTION();
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

	return ( ( (unsigned int)( random() % 100) + 1 <= this_percentage ) );
}

SessionTrack* TCPTrack::init_sessiontrack(const Packet &pkt) 
{
	/* pkt is the refsyn, SYN packet reference for starting ttl bruteforce */
	SessionTrackKey key = {pkt.ip->daddr, pkt.tcp->source, pkt.tcp->dest};
	SessionTrackMap::iterator it = sex_map.find(key);
	if (it != sex_map.end())
		return &(it->second);
	else {
		if(sex_map.size() == runconfig.max_sex_track) {
			/* if we reach sextrackmax probably we have a lot of dead sessions tracked */
			/* we can make a complete clear() resetting sex_map without problems */
			sex_map.clear();
		}
		return &(sex_map.insert(pair<SessionTrackKey, SessionTrack>(key, pkt)).first->second);
	}
}

void TCPTrack::clear_session(SessionTrackMap::iterator stm_it)
{
	/* 
	 * clear_session don't remove conntrack immediatly, at the first call
	 * set the "shutdown" bool variable, at the second clear it, this
	 * because of double FIN-ACK and RST-ACK happening between both hosts.
	 */
	SessionTrack& st = stm_it->second;
	if (st.shutdown == false) {
		st.selflog(__func__, "shutdown false set to be true");
		st.shutdown = true;
	} else {
		st.selflog(__func__, "shutdown true, deleting session");
		sex_map.erase(stm_it);
	}
}

TTLFocus* TCPTrack::init_ttlfocus(unsigned int daddr) 
{
	TTLFocusMap::iterator it = ttlfocus_map.find(daddr);
	if (it != ttlfocus_map.end())
		return &(it->second);	
	else
		return &(ttlfocus_map.insert(pair<const unsigned int, TTLFocus>(daddr, daddr)).first->second);
}

/* 
 * enque_ttl_probe has not the intelligence to understand if TTL bruteforcing 
 * is required or not more. Is called in different section of code
 */
void TCPTrack::enque_ttl_probe(const Packet &delayed_syn_pkt, TTLFocus& ttlfocus)
{
	/* 
	 * the first packet (the SYN) is used as starting point
	 * in the enque_ttl_burst to generate the series of 
	 * packets able to detect the number of hop distance 
	 * between our peer and the remote peer. the packet
	 * is lighty modify (ip->id change) and checksum fixed
	 */

	if(!ttlfocus.isProbeIntervalPassed(clock))
		return;

	if (analyze_ttl_stats(ttlfocus))
		return;
	
	/* create a new packet; the copy is done to keep refsyn ORIGINAL */
	Packet *injpkt = new Packet(delayed_syn_pkt);
	injpkt->mark(TTLBFORCE, SEND, INNOCENT, GOOD);

	/* 
	 * if TTL expire and is generated and ICMP TIME EXCEEDED,
	 * the iphdr is preserved and the tested_ttl found
	 */
	ttlfocus.sent_probe++;
	injpkt->ip->ttl = ttlfocus.sent_probe;
	injpkt->tcp->source = ttlfocus.puppet_port;
	injpkt->tcp->seq = htonl(ttlfocus.rand_key + ttlfocus.sent_probe);
	injpkt->ip->id = (ttlfocus.rand_key % 64) + ttlfocus.sent_probe;

	p_queue.insert(HIGH, *injpkt);
	
	ttlfocus.scheduleNextProbe();

	snprintf(injpkt->debugbuf, LARGEBUF, "Injecting probe %d [exp %d min work %d]",
		ttlfocus.sent_probe, ttlfocus.expiring_ttl, ttlfocus.min_working_ttl
	);
	injpkt->selflog(__func__, injpkt->debugbuf);
}

bool TCPTrack::analyze_ttl_stats(TTLFocus &ttlfocus)
{
	if (ttlfocus.sent_probe == runconfig.max_ttl_probe) {
		ttlfocus.status = TTL_UNKNOWN;
		return true;
	}
	return false;
}

void TCPTrack::analyze_incoming_ttl(Packet &pkt)
{
	TTLFocusMap::iterator it = ttlfocus_map.find(pkt.ip->saddr);
	TTLFocus *ttlfocus;

	if (it != ttlfocus_map.end()) 
	{
		ttlfocus = &(it->second);
		if (ttlfocus->status == TTL_KNOWN && ttlfocus->synack_ttl != pkt.ip->ttl) 
		{
			/* probably a topology change has happened - we need a solution wtf!!  */
			snprintf(pkt.debugbuf, LARGEBUF, 
				"net topology change! #probe %d [exp %d min work %d synack ttl %d]",
				ttlfocus->sent_probe, ttlfocus->expiring_ttl, 
				ttlfocus->min_working_ttl, ttlfocus->synack_ttl
			);
			pkt.selflog(__func__, pkt.debugbuf);
		}
	}
}


Packet* TCPTrack::analyze_incoming_icmp(Packet &timeexc)
{
	const struct iphdr *badiph;
	const struct tcphdr *badtcph;
	TTLFocusMap::iterator ttlfocus_map_it;

	badiph = (struct iphdr *)((unsigned char *)timeexc.icmp + sizeof(struct icmphdr));
	badtcph = (struct tcphdr *)((unsigned char *)badiph + (badiph->ihl * 4));

	ttlfocus_map_it = ttlfocus_map.find(badiph->daddr);
	if (ttlfocus_map_it != ttlfocus_map.end() && badiph->protocol == IPPROTO_TCP) {
		TTLFocus *ttlfocus = &(ttlfocus_map_it->second);
		unsigned char expired_ttl = badiph->id - (ttlfocus->rand_key % 64);
		unsigned char exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

		if (ttlfocus->status != TTL_KNOWN && expired_ttl == exp_double_check) {
			ttlfocus->received_probe++;

			if (expired_ttl > ttlfocus->expiring_ttl) {
				snprintf(ttlfocus->debugbuf, LARGEBUF, "good TTL: recv %d", expired_ttl);
				ttlfocus->selflog(__func__, ttlfocus->debugbuf);
				ttlfocus->expiring_ttl = expired_ttl;
			}
			else  {
				snprintf(ttlfocus->debugbuf, LARGEBUF, "BAD TTL!: recv %d", expired_ttl);
				ttlfocus->selflog(__func__, ttlfocus->debugbuf);
			}
		}
		p_queue.remove(timeexc);
		delete &timeexc;
		return NULL;
	}
	
	return &timeexc;
}

Packet* TCPTrack::analyze_incoming_synack(Packet &synack)
{
	TTLFocusMap::iterator it = ttlfocus_map.find(synack.ip->saddr);
	TTLFocus *ttlfocus;

	/* NETWORK is src: dest port and source port inverted and saddr are used, 
	 * source is put as last argument (puppet port)
	 */

	if (it != ttlfocus_map.end()) {
		
		ttlfocus = &(it->second);

		snprintf(synack.debugbuf, LARGEBUF, "puppet %d Incoming SYN/ACK", ntohs(ttlfocus->puppet_port));
		synack.selflog(__func__, synack.debugbuf);

		if (synack.tcp->dest == ttlfocus->puppet_port) {
			unsigned char discern_ttl =  ntohl(synack.tcp->ack_seq) - ttlfocus->rand_key - 1;

			ttlfocus->received_probe++;
			ttlfocus->status = TTL_KNOWN;

			if (ttlfocus->min_working_ttl > discern_ttl && discern_ttl <= ttlfocus->sent_probe) { 
				ttlfocus->min_working_ttl = discern_ttl;
				ttlfocus->expiring_ttl = discern_ttl - 1;
				ttlfocus->synack_ttl = synack.ip->ttl;
			}

			snprintf(ttlfocus->debugbuf, LARGEBUF, "discerned TTL %d", discern_ttl);
			ttlfocus->selflog(__func__, ttlfocus->debugbuf);

			/* 
			* this code flow happens only when the SYN ACK is received, due to
			* a SYN send from the "puppet port". this kind of SYN is used only
			* for discern TTL, and this mean a REFerence-SYN packet is present in
			* the packet queue. Now that ttl has been detected, the real SYN could
			* be send.
			*/
		
			mark_real_syn_packets_SEND(synack.ip->saddr);
			p_queue.remove(synack);
			delete &synack;
			return NULL;
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
		 */

	}
	
	return &synack;
}

Packet* TCPTrack::analyze_incoming_rstfin(Packet &rstfin)
{
	SessionTrackKey key = {rstfin.ip->saddr, rstfin.tcp->dest, rstfin.tcp->source};
	SessionTrackMap::iterator stm_it = sex_map.find(key);

	if (stm_it != sex_map.end()) {
		rstfin.selflog(__func__, "Session found");
		clear_session(stm_it);
	} else {
		rstfin.selflog(__func__, "Session not found!");
	}

	return &rstfin;
}

void TCPTrack::manage_outgoing_packets(Packet &pkt)
{
	TTLFocus *ttlfocus;
	SessionTrackKey key = {pkt.ip->daddr, pkt.tcp->source, pkt.tcp->dest};
	SessionTrackMap::iterator sex_map_it;
	SessionTrack *session;

	/* 
	 * session get return an existing session or even NULL, 
	 */
	if (pkt.tcp->syn) {
		init_sessiontrack(pkt);
		ttlfocus = init_ttlfocus(pkt.ip->daddr);

		pkt.selflog(__func__, "incoming SYN");

		/* if sniffjoke had not yet the minimum working ttl, continue the starting probe */
		if (ttlfocus->status == TTL_BRUTALFORCE) {
			ttlfocus->selflog(__func__, "SYN retrasmission, keep pkt");
			pkt.status = KEEP; 
			return;
		}
	}

	sex_map_it = sex_map.find(key);

	if (sex_map_it != sex_map.end()) 
	{
		session = &(sex_map_it->second);
		session->packet_number++;
		if (pkt.tcp->fin || pkt.tcp->rst) 
		{
			pkt.selflog(__func__, "handling closing flags");
			clear_session(sex_map_it);
			   
		} else {
			/* update_session_stat(xml_stat_root, ct); */

			/* a closed or shutdown session don't require to be hacked */
			pkt.selflog(__func__, "injecting pkt in queue");
			inject_hack_in_queue(pkt, session);		
		}
	}
}

void TCPTrack::mark_real_syn_packets_SEND(unsigned int daddr)
{
	Packet *pkt = p_queue.get(ANY_STATUS, ANY_SOURCE, TCP, false);
	while (pkt != NULL) {
		if (pkt->tcp->syn && pkt->ip->daddr == daddr) {
			pkt->selflog(__func__, "the orig SYN shift from keep to send");
			pkt->status = SEND;
		}
		pkt = p_queue.get(ANY_STATUS, ANY_SOURCE, TCP, true);
	}
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
void TCPTrack::inject_hack_in_queue(Packet &orig_pkt, const SessionTrack *session)
{
	vector<PluginTrack>::iterator it;
	PluginTrack *hppe;
	
	/* SELECT APPLICABLE HACKS */
	for ( it = hack_pool.begin(); it != hack_pool.end(); it++ ) {
		hppe = &(*it);
		hppe->enabled = true;
		hppe->enabled &= hppe->selfObj->Condition(orig_pkt);
		hppe->enabled &= percentage(
					session->packet_number,
					hppe->selfObj->hackFrequency,
					runconfig.portconf[ntohs(orig_pkt.tcp->dest)]
				);
	}

	/* -- RANDOMIZE HACKS APPLICATION */
	random_shuffle( hack_pool.begin(), hack_pool.end() );

	/* -- FINALLY, SEND THE CHOOSEN PACKET(S) */
	for ( it = hack_pool.begin(); it != hack_pool.end(); it++ ) 
	{
		/* must be moved in the do/while loop based on HackPacket->num_pkt_gen */
		vector<Packet*>::iterator hack_it;
		Packet *injpkt;

		hppe = &(*it);
		if(!hppe->enabled) 
			continue;

		hppe->selfObj->createHack(orig_pkt);
		
		for ( hack_it = hppe->selfObj->pktVector.begin() ; hack_it < hppe->selfObj->pktVector.end(); hack_it++ ) {
		
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
			injpkt->mark(LOCAL, SEND, EVIL);

			snprintf(injpkt->debugbuf, MEDIUMBUF, "Injected from %s", hppe->selfObj->hackName);
			injpkt->selflog(__func__, injpkt->debugbuf);

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
		                        SJ_RUNTIME_EXCEPTION();
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
void TCPTrack::last_pkt_fix(Packet &pkt)
{
	const TTLFocus *ttlfocus;
	TTLFocusMap::iterator ttlfocus_map_it;

	if (pkt.proto != TCP) {
		return;
	} else if (pkt.source != TUNNEL && pkt.source != LOCAL) {
		pkt.fixIpTcpSum();
		return;
	}
	
	/* 1st check: WHAT VALUE OF TTL GIVE TO THE PACKET ? */
	ttlfocus_map_it = ttlfocus_map.find(pkt.ip->daddr);

	if (ttlfocus_map_it != ttlfocus_map.end())
		ttlfocus = &(ttlfocus_map_it->second);
	else
		ttlfocus = NULL;
	/* end 1st check */

	/* 2nd check: what kind of hacks will be apply ? */
	if(pkt.wtf == RANDOMDAMAGE) 
	{
#define RANDVALUE	(random() % 100)

		pkt.wtf = GUILTY;

		if( RANDVALUE > 25)
			pkt.wtf = PRESCRIPTION;

		if( RANDVALUE > 80 ) 
			pkt.wtf = MALFORMED;
	}

	/* hack selection, second stage */
	switch(pkt.wtf) {
		case PRESCRIPTION:
			if(ttlfocus != NULL && ttlfocus->status != TTL_UNKNOWN)
				break;

			/* else, became MALFORMED below */
			pkt.wtf = MALFORMED;
		case MALFORMED:
			if(!pkt.checkUncommonIPOPT())
				break;

			/* else, became a GUILTY packet */
			pkt.wtf = GUILTY;
		case GUILTY:
		case INNOCENT:
			break;
		case RANDOMDAMAGE:
		case JUDGEUNASSIGNED:
		default:
			debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
			SJ_RUNTIME_EXCEPTION();
	}

	/* TTL modification - every packet subjected if possible */
	if (ttlfocus != NULL && ttlfocus->status != TTL_UNKNOWN) 
	{
		if (pkt.wtf == PRESCRIPTION) 
			pkt.ip->ttl = ttlfocus->expiring_ttl - (random() % 5);
		else
			pkt.ip->ttl = ttlfocus->min_working_ttl + (random() % 5);
	} else 
	{
		pkt.ip->ttl = STARTING_ARB_TTL + (random() % 100);
	}	

	/* IP options, every packet subject if possible, and MALFORMED will be apply */
	if(pkt.wtf == MALFORMED) {	
		pkt.Inject_IPOPT(/* corrupt ? */ true, /* strip previous options */ true);
	} else {
		if (!pkt.checkUncommonIPOPT() && RANDOMPERCENT(20))
			pkt.Inject_IPOPT(/* corrupt ? */ false, /* strip previous options ? */ false);
	}

	// VERIFY - TCP doesn't cause a failure of the packet, the BAD TCPOPT will be used always
	if (!pkt.checkUncommonTCPOPT() && RANDOMPERCENT(20)) {
		if RANDOMPERCENT(50)
			pkt.Inject_TCPOPT(/* corrupt ? */ false, /* stript previous ? */ true);
		else
			pkt.Inject_TCPOPT(/* corrupt ? */ true, /* stript previous ? */ true);		
	}
	
	/* fixing the mangled packet */
	pkt.fixIpTcpSum();

	/* corrupted checksum application if required */
	if (pkt.wtf == GUILTY)
		pkt.tcp->check ^= (0xd34d ^ (unsigned short)random());

	pkt.selflog(__func__, "Packet ready to be send");
}

/* the packet is add in the packet queue for be analyzed in a second time */
bool TCPTrack::writepacket(const source_t source, const unsigned char *buff, int nbyte)
{
	try {
		Packet *pkt = new Packet(buff, nbyte);
		pkt->mark(source, YOUNG, INNOCENT, GOOD);
	
		/* 
		* the packet from the tunnel are put with lower priority and the
		* hack-packet, injected from sniffjoke, are put in the higher one.
		* when the software loop for in p_queue.get(status, source, proto) the 
		* forged packet are sent before the originals one.
		*/
		p_queue.insert(LOW, *pkt);
		
		youngpacketspresent = true;
	
		return true;
		
	} catch (exception &e) {
		/* malformed packet, ignored */
		return false;
	}
}

Packet* TCPTrack::readpacket()
{
	Packet *pkt = p_queue.get(SEND, ANY_SOURCE, ANY_PROTO, false);
	if (pkt != NULL) {
		p_queue.remove(*pkt);
		if (runconfig.active == true)
			last_pkt_fix(*pkt);
	}
	return pkt;
}

/* 
 * this is the "second time", the received packet are assigned in a tracked TCP session,
 * for understand which kind of mangling should be apply. maybe not all packets is sent 
 * immediatly, this happens when sniffjoke require some time (and some packets) for
 * detect the hop distance between the remote peer.
 *
 * as defined in sniffjoke.h, the "status" variable could have these status:
 * SEND (packet marked as sendable)
 * KEEP (packet to keep and wait)
 * YOUNG (packet received, here analyzed for the first time)
 *
 * analyze_packets_queue is called from the main.cc poll() block
 */
void TCPTrack::analyze_packets_queue()
{
	Packet *pkt;
	TTLFocusMap::iterator ttlfocus_map_it;
	TTLFocus *ttlfocus;
	
	clock_gettime(CLOCK_REALTIME, &clock);

	if(youngpacketspresent == false)
		goto analyze_keep_packets;
	else
		youngpacketspresent = false;

	pkt = p_queue.get(YOUNG, NETWORK, ICMP, false);
	while (pkt != NULL) {
		
		analyze_incoming_ttl(*pkt);
		
		/* 
		 * a TIME_EXCEEDED packet should contains informations
		 * for discern HOP distance from a remote host
		 */
		if (pkt->icmp->type == ICMP_TIME_EXCEEDED) {
			pkt = analyze_incoming_icmp(*pkt);
		}

		pkt = p_queue.get(YOUNG, NETWORK, ICMP, true);
	}

	/* 
	 * incoming TCP. sniffjoke algorithm open/close sessions and detect TTL
	 * lists analyzing SYN+ACK and FIN|RST packet
	 */
	pkt = p_queue.get(YOUNG, NETWORK, TCP, false);
	while (pkt != NULL) {
		
		analyze_incoming_ttl(*pkt);

		if (pkt->tcp->syn && pkt->tcp->ack)
			pkt = analyze_incoming_synack(*pkt);

		if (pkt != NULL && pkt->status == YOUNG && (pkt->tcp->rst || pkt->tcp->fin))
			pkt = analyze_incoming_rstfin(*pkt);   

		pkt = p_queue.get(YOUNG, NETWORK, TCP, true);
	}

	/* outgoing TCP packets ! */
	pkt = p_queue.get(YOUNG, TUNNEL, TCP, false);
	while (pkt != NULL) {

		/* no hacks required for this destination port */
		if (runconfig.portconf[ntohs(pkt->tcp->dest)] == NONE) {
			pkt->status = SEND; 
			continue;
		}

		/* 
		 * create/close session, check ttlfocus and start new discovery, 
		 * this function contains the core functions of sniffjoke: 
		 * enque_ttl_probe and inject_hack_in_queue 
		 *
		 * those packets had ttlfocus set inside
		 */
		manage_outgoing_packets(*pkt);

		pkt = p_queue.get(YOUNG, TUNNEL, TCP, true);
	}

	/* all YOUNG packets must be sent immediatly */
	pkt = p_queue.get(YOUNG, ANY_SOURCE, ANY_PROTO, false);
	while (pkt != NULL) {
		pkt->status = SEND;
		pkt = p_queue.get(YOUNG, ANY_SOURCE, ANY_PROTO, true);
	}

analyze_keep_packets:

	pkt = p_queue.get(KEEP, TUNNEL, TCP, false);
	while (pkt != NULL) {
		ttlfocus_map_it = ttlfocus_map.find(pkt->ip->daddr);
		if (ttlfocus_map_it == ttlfocus_map.end()) {
			debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
			SJ_RUNTIME_EXCEPTION();
		}
		
		ttlfocus = &(ttlfocus_map_it->second);
		if (ttlfocus->status == TTL_BRUTALFORCE)  {
			pkt->selflog(__func__, "ttl status BForce, pkt KEEP");
			enque_ttl_probe(*pkt, *ttlfocus);
		}
		pkt = p_queue.get(KEEP, TUNNEL, TCP, true);
	}
}

/*
 * this function set SEND stats to all packets, is used when sniffjoke must not 
 * mangle the packets 
 */
void TCPTrack::force_send(void)
{
	Packet *pkt = p_queue.get(false);
	while (pkt != NULL) {
		pkt->status = SEND;
		pkt = p_queue.get(true);
	}
}
