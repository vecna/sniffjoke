/*
 * SniffJoke project: this is the file most edited
 * http://www.delirandom.net/sniffjoke, this file in G's codesearch:
 * http://www.delirandom.net/sniffjoke/sniffjoke-0.3/sniffjoke-src/TCPTrack.cc
 */

#include "SjUtils.h"
#include "TCPTrack.h"

#include <cstdlib>
#include <cstring>
#include <ctime>

#include <arpa/inet.h>

#define DATADEBUG // WARNING: it run a mkdir /tmp/datadump 
#ifdef DATADEBUG
#include "Optional_DataDebug.h"
static DataDebug *dd;
#endif

// define PACKETDEBUG enable session debug, ttl bruteforce 
#define PACKETDEBUG 
// define HACKSDEBUG enable dump about packet injected
#define HACKSDEBUG

/* Max Number of options injectable */
#define MAXOPTINJ			12
#define MAXHACKS			7

#define STARTING_ARB_TTL	46

#define UNCHANGED_SIZE		(-1)

enum priority_t { HIGH = 0, LOW = 1 };

TCPTrack::TCPTrack(SjConf *sjconf)
	: p_queue(2), sex_list(), ttlfocus_map()
{
	runcopy = sjconf->running;
	maxttlprobe = runcopy->max_ttl_probe;

	/* random pool initialization */
	for (int i = 0; i < ((random() % 40) + 3); i++) 
		srandom((unsigned int)time(NULL) ^ random());

#ifdef DATADEBUG
        dd = new DataDebug();
#endif

	internal_log(NULL, DEBUG_LEVEL, "TCPTrack()");
}

TCPTrack::~TCPTrack() 
{
	internal_log(NULL, DEBUG_LEVEL, "~TCPTrack()");
}

bool TCPTrack::check_evil_packet(const unsigned char *buff, int nbyte)
{
	struct iphdr *ip = (struct iphdr *)buff;
 
	if (nbyte < sizeof(struct iphdr)) {
#ifdef DATADEBUG
		dd->InfoMsg("Packet", "check_evil_packet: if (nbyte < sizeof(struct iphdr))");
#endif
		return false;
	}

	if (nbyte != ntohs(ip->tot_len)) {
#ifdef DATADEBUG
		dd->InfoMsg("Packet", "check_evil_packet: if (nbyte != ntohs(ip->tot_len))");
#endif
		return false;
	}

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp;
		int iphlen;
		int tcphlen;

		iphlen = ip->ihl * 4;

		if (nbyte < iphlen + sizeof(struct tcphdr)) {
#ifdef DATADEBUG
			dd->InfoMsg("Packet", "check_evil_packet: if (nbyte < iphlen + sizeof(struct tcphdr))");
#endif
			return false;
		}

		tcp = (struct tcphdr *)((unsigned char *)ip + iphlen);
		tcphlen = tcp->doff * 4;
		
		if (ntohs(ip->tot_len) < iphlen + tcphlen) {
#ifdef DATADEBUG
			dd->InfoMsg("Packet", "check_evil_packet: if (ntohs(ip->tot_len) < iphlen + tcphlen)");
#endif
			return false;
		}
	}
	
	return true;
}

/* the packet is add in the packet queue for be analyzed in a second time */
bool TCPTrack::writepacket(const source_t source, const unsigned char *buff, int nbyte)
{
	Packet *pkt;
	
	if (check_evil_packet(buff, nbyte) == false)
		return false;

	/* 
	 * the packet_id is required because the OS should generate 
	 * duplicate SYN when didn't receive the expected answer. 
	 *
	 * this happens when the first SYN is blocked for TTL bruteforce
	 * routine. 
	 *
	 * the nbyte is added with the max ip/tcp option injection because
	 * the packets options could be modified by last_pkt_fix
	 */

	pkt = new Packet(nbyte + MAXOPTINJ*3, buff, nbyte);
	pkt->source = source;
	pkt->status = YOUNG;
	pkt->wtf = INNOCENT;

	/* 
	 * the packet from the tunnel are put with lower priority and the
	 * hack-packet, injected from sniffjoke, are put in the higher one.
	 * when the software loop for in p_queue.get(status, source, proto) the 
	 * forged packet are sent before the originals one.
	 */
	p_queue.insert(LOW, *pkt);
	
	return true;
}

Packet* TCPTrack::readpacket() {
	Packet *pkt = p_queue.get(SEND, ANY_SOURCE, ANY_PROTO, false);
	if (pkt != NULL) {
		p_queue.remove(*pkt);
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
 * analyze_packets_queue is called from the main.cc select() block
 */
void TCPTrack::analyze_packets_queue() 
{
	Packet *pkt;
	TTLFocus *ttlfocus;
	TTLFocusMap::iterator it;

#ifdef DATADEBUG
        dd->InfoMsg("Packet", "analyze_packets_queue");
        dd->Dump_Packet(p_queue);
#endif

	pkt = p_queue.get(YOUNG, NETWORK, ICMP, false);
	while (pkt != NULL) {
		/* 
		 * a TIME_EXCEEDED packet should contains informations
		 * for discern HOP distance from a remote host
		 */
		if (pkt->icmp->type == ICMP_TIME_EXCEEDED)
			pkt = analyze_incoming_icmp(*pkt);

		/* if packet exist again = is not destroyed by analyze function */
		if (pkt != NULL)
			pkt->status = SEND;
		
		pkt = p_queue.get(YOUNG, NETWORK, ICMP, true);
	}

	/* 
	 * incoming TCP. sniffjoke algorithm open/close sessions and detect TTL
	 * lists analyzing SYN+ACK and FIN|RST packet
	 */
	pkt = p_queue.get(YOUNG, NETWORK, TCP, false);
	while (pkt != NULL) {
		if (pkt->tcp->syn && pkt->tcp->ack)
			pkt = analyze_incoming_synack(*pkt);

		if (pkt != NULL && pkt->status == YOUNG && (pkt->tcp->rst || pkt->tcp->fin))
			pkt = analyze_incoming_rstfin(*pkt);   

		/* if packet exist again = is not destroyed by analyze function */
		if (pkt != NULL && pkt->status == YOUNG)
			pkt->status = SEND;
			
		pkt = p_queue.get(YOUNG, NETWORK, TCP, true);
	}

	/* outgoing TCP packets ! */
	pkt = p_queue.get(YOUNG, TUNNEL, TCP, false);
	while (pkt != NULL) {

		/* no hacks required for this destination port */
		if (runcopy->portconf[ntohs(pkt->tcp->dest)] == NONE) {
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

		/* all outgoing packets, exception for starting SYN (status = KEEP), are sent immediatly */
		if (pkt->status == YOUNG)
			pkt->status = SEND;
			
		pkt = p_queue.get(YOUNG, TUNNEL, TCP, true);
	}

	pkt = p_queue.get(KEEP, TUNNEL, TCP, false);
	while (pkt != NULL) {
		it = ttlfocus_map.find(pkt->ip->daddr);
		if (it == ttlfocus_map.end())
			 check_call_ret("unforeseen bug: ttlfocus == NULL in TCPTrack.cc, contact the package mantainer, sorry. analyze_packet_queue", 0, -1, true);
		
		ttlfocus = &(it->second);
		if (ttlfocus->status == TTL_BRUTALFORCE)  {
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG, "status BRUTALFORCE for %s: %d %d pkt is KEEP (%d), send %d probe, rcvd %d probe",
				inet_ntoa(*((struct in_addr *)&ttlfocus->daddr)) ,
				ntohs(pkt->tcp->source), 
				ntohs(pkt->tcp->dest),
				ttlfocus->status, ttlfocus->sent_probe, ttlfocus->received_probe
			);
#endif
			enque_ttl_probe(*pkt, *ttlfocus);
		}
		pkt = p_queue.get(KEEP, TUNNEL, TCP, true);
	}

	/* all others YOUNG packets must be sent immediatly */
	pkt = p_queue.get(YOUNG, ANY_SOURCE, ANY_PROTO, false);
	while (pkt != NULL) {
		pkt->status = SEND;
		pkt = p_queue.get(YOUNG, ANY_SOURCE, ANY_PROTO, true);
	}
	
}

/*
 * this function set SEND stats to all packets, is used when sniffjoke must not 
 * mangle the packets 
 */
void TCPTrack::force_send()
{
#ifdef PACKETDEBUG
	int counter = 0;
#endif
	Packet *pkt = p_queue.get(false);
	while (pkt != NULL) {
#ifdef PACKETDEBUG
		counter++;
#endif
		pkt->status = SEND;
		pkt = p_queue.get(true);
	}
#ifdef PACKETDEBUG
	internal_log(NULL, PACKETS_DEBUG, "force_send had converted %d packets to SEND status", counter);
#endif
}

/* 
 * last packet fix! is the catch all for all packets, they should be:
 *   PRESCRIPTION pkt, that expire BEFORE REACH destination addr
 *   GUILTY pkt, that have some kind of error to be discarged from the dest
 *   INNOCENT pkt, valid packet that reach destination address
 *
 *   otherwise, the should be the packet received from the tunnel. They 
 *   use the same treatment as INNOCENT packets.
 *
 *   at the moment, no hacks use INNOCENT flag.
 */
void TCPTrack::last_pkt_fix(Packet &pkt)
{
	const TTLFocus *ttlfocus;
	TTLFocusMap::iterator it;
	const time_t now = time(NULL);
	int i;

	/* 
	 * packets different from TCP, and packets without ttl focus struct are
	 * SEND immediatly
	 */ 
#ifdef PACKETDEBUG
	if (pkt.proto == TCP) 
		internal_log(NULL, PACKETS_DEBUG,
					"last_pkt_fix (TCP) : id %u (lo:%d %s:%d) proto %d source %d", 
					ntohs(pkt.ip->id), 
					ntohs(pkt.tcp->source),
					inet_ntoa(*((struct in_addr *)&pkt.ip->daddr)) ,
					ntohs(pkt.tcp->dest), 
					pkt.ip->protocol, 
					pkt.source
		);
	else 
		internal_log(NULL, PACKETS_DEBUG,
					"last_pkt_fix (!TCP): id %u proto %d source %d", 
					ntohs(pkt.ip->id), 
					pkt.ip->protocol, 
					pkt.source
		);
#endif

	if (pkt.proto != TCP || pkt.source == TTLBFORCE)
		return;

	it = ttlfocus_map.find(pkt.ip->daddr);
	if (it == ttlfocus_map.end())
		return;

	ttlfocus = &(it->second);
	/* 1st check: HOW MANY TTL GIVE TO THE PACKET ? */
	if (ttlfocus->status == TTL_UNKNOW) {
		if (pkt.wtf == PRESCRIPTION)
			pkt.wtf = GUILTY;

		pkt.ip->ttl = STARTING_ARB_TTL + (random() % 100);
	} else {
		if (pkt.wtf == PRESCRIPTION) 
			pkt.ip->ttl = ttlfocus->expiring_ttl; 
		else	/* GUILTY or INNOCENT */
			pkt.ip->ttl = (ttlfocus->expiring_ttl + (random() % 5) + 1);

	}
	
	/* 2nd check: CAN WE INJECT IP/TCP OPTIONS INTO THE PACKET ? */
	if (!pkt.tcp->syn && pkt.wtf != INNOCENT) {
		if (runcopy->SjH__inject_ipopt) {
			/* we can inject if we have at least 4 bytes free
			 * in point of fact we does not need 4 bytes, because we can strip also
			 * options just present in the packet
			 */
			if ((pkt.pbuf_size - ntohs(pkt.ip->tot_len)) > 4)
				if (percentage(1, 100))
					SjH__inject_ipopt(pkt);
		}

		if (runcopy->SjH__inject_tcpopt) {
			/* we can inject if we have 8 bytes free
			 * in point of fact we does not need 8 bytes, because we can strip also
			 * options just present in the packet
			 */
			if ((pkt.pbuf_size - ntohs(pkt.ip->tot_len)) > 8 && !check_uncommon_tcpopt(pkt.tcp))
				if (percentage(25, 100))
					SjH__inject_tcpopt(pkt);
		}
	}

	/* 3rd check: GOOD CHECKSUM or BAD CHECKSUM ? */
	pkt.fixIpTcpSum();

	if (pkt.wtf == GUILTY)
		pkt.tcp->check ^= (0xd34d * (unsigned short)random() +1);
}


Packet* TCPTrack::analyze_incoming_icmp(Packet &timeexc)
{
	const struct iphdr *badiph;
	const struct tcphdr *badtcph;
	TTLFocusMap::iterator it;

#ifdef DATADEBUG
        dd->InfoMsg("TTL", "analyze_incoming_icmp");
        dd->Dump_TTL(ttlfocus_map);
#endif

	badiph = (struct iphdr *)((unsigned char *)timeexc.icmp + sizeof(struct icmphdr));
	badtcph = (struct tcphdr *)((unsigned char *)badiph + (badiph->ihl * 4));

	it = ttlfocus_map.find(badiph->daddr);
	if (it != ttlfocus_map.end() && badiph->protocol == IPPROTO_TCP) {
		TTLFocus *ttlfocus = &(it->second);
		unsigned char expired_ttl = badiph->id - (ttlfocus->rand_key % 64);
		unsigned char exp_double_check = ntohl(badtcph->seq) - ttlfocus->rand_key;

		if (ttlfocus->status != TTL_KNOW && expired_ttl == exp_double_check) {
			ttlfocus->received_probe++;

			if (expired_ttl > ttlfocus->expiring_ttl) {
#ifdef PACKETDEBUG
				internal_log(NULL, PACKETS_DEBUG, "TTL OK: (sent %d recvd %d) previous %d now %d", 
					ttlfocus->sent_probe, ttlfocus->received_probe,
					ttlfocus->expiring_ttl, expired_ttl
				);
#endif
				ttlfocus->expiring_ttl = expired_ttl;
			}
#ifdef PACKETDEBUG
			else {
				internal_log(NULL, PACKETS_DEBUG, "TTL BAD: (sent %d recvd %d) previous %d now %d",
					ttlfocus->sent_probe, ttlfocus->received_probe,
					ttlfocus->expiring_ttl, expired_ttl
				);
			}
#endif
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

#ifdef DATADEBUG
        dd->InfoMsg("Session", "analyzie_incoming_synack, from: %s", inet_ntoa(*((struct in_addr *)&synack.ip->saddr)));
        dd->Dump_Session(sex_list);
#endif

	/* NETWORK is src: dest port and source port inverted and saddr are used, 
	 * source is put as last argument (puppet port)
	 */

	if (it != ttlfocus_map.end()) {
		
		ttlfocus = &(it->second);

#ifdef PACKETDEBUG
		internal_log(NULL, PACKETS_DEBUG, "SYN/ACK (saddr %s) seq %08x seq_ack %08x - dport %d sport %d puppet %d",
					inet_ntoa(*((struct in_addr *)&synack.ip->saddr)),
					ntohl(synack.tcp->seq),
					ntohl(synack.tcp->ack_seq),
					ntohs(synack.tcp->dest), 
					ntohs(synack.tcp->source),
					ntohs(ttlfocus->puppet_port)
		);
#endif

		if (synack.tcp->dest == ttlfocus->puppet_port) {
			unsigned char discern_ttl =  ntohl(synack.tcp->ack_seq) - ttlfocus->rand_key - 1;

			ttlfocus->received_probe++;
			ttlfocus->status = TTL_KNOW;

			if (ttlfocus->min_working_ttl > discern_ttl && discern_ttl <= ttlfocus->sent_probe) 
				ttlfocus->min_working_ttl = discern_ttl;

#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG,
						"discern_ttl %d: min working ttl %d expiring ttl %d recv probe %d sent probe %d",
						discern_ttl,
						ttlfocus->min_working_ttl,
						ttlfocus->expiring_ttl,
						ttlfocus->received_probe,
						ttlfocus->sent_probe
			);
#endif

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
	SessionTrack *session = sex_list.get(rstfin.ip->saddr, rstfin.tcp->dest, rstfin.tcp->source);

#ifdef PACKETDEBUG
	internal_log(NULL, PACKETS_DEBUG,
				"RST/FIN received (NET): ack_seq %08x, sport %d dport %d saddr %s",
				rstfin.tcp->ack_seq, 
				ntohs(rstfin.tcp->source),
				ntohs(rstfin.tcp->dest),
				inet_ntoa(*((struct in_addr *)&rstfin.ip->saddr))
	);
#endif

	if (session != NULL) {
		/* 
		 * clear_session don't remove conntrack immediatly, at the first call
		 * set the "shutdown" bool variable, at the second clear it, this
		 * because of double FIN-ACK and RST-ACK happening between both hosts.
		 */
		sex_list.clear_session(session);
	}
	
	return &rstfin;
}

void TCPTrack::manage_outgoing_packets(Packet &pkt)
{
	TTLFocus *ttlfocus;
	SessionTrack *session;

	/* 
	 * session get return an existing session or even NULL, 
	 */
	if (pkt.tcp->syn) {
		init_sessiontrack(pkt);
		ttlfocus = init_ttlfocus(pkt.ip->daddr);

#ifdef PACKETDEBUG
		internal_log(NULL, PACKETS_DEBUG,
					"SYN from TUNNEL:%d %s:%d",
					ntohs(pkt.tcp->source),
					inet_ntoa(*((struct in_addr *)&pkt.ip->daddr)),
					ntohs(pkt.tcp->dest) 
		);
#endif
		/* if sniffjoke had not yet the minimum working ttl, continue the starting probe */
		if (ttlfocus->status == TTL_BRUTALFORCE) {
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG, "SYN retransmission - DROPPED");
#endif
			pkt.status = KEEP; 
			return;
		}
	}

	/* all outgoing packets, exception for starting SYN, are SEND immediatly */	
	pkt.status = SEND;
	session = sex_list.get(pkt);
	if (session != NULL && (pkt.tcp->rst || pkt.tcp->fin)) {
#ifdef PACKETDEBUG
		internal_log(NULL, PACKETS_DEBUG,
					"FIN/RST (TUN) clear: seq %08x seq_ack %08x (rst %d fin %d ack %d) dport %d sport %d)",
					ntohl(pkt.tcp->seq),
					ntohl(pkt.tcp->ack_seq),
					pkt.tcp->rst, pkt.tcp->fin, 
					pkt.tcp->ack,
					ntohs(pkt.tcp->dest), ntohs(pkt.tcp->source)
		);
#endif
		/* 
		 * clear_session don't remove conntrack immediatly, at the first 
		 * invoke set "shutdown" variable, at the second clear it 
		 */
		 sex_list.clear_session(session);
		   
		 /* a closed or shutdown session don't require to be hacked */
	}
	
	if (session == NULL)
		return;
	
	session->packet_number++;
				
	/* update_session_stat(xml_stat_root, ct); */

	/* a closed or shutdown session don't require to be hacked */
	if (pkt.tcp->rst || pkt.tcp->fin)
		return;

	inject_hack_in_queue(pkt, session);
}

/* 
 * inject_hack_in_queue is one of the core function in sniffjoke:
 *
 * the hacks are, for the most, two kinds.
 *
 * one kind require the knowledge of exactly hop distance between the two hops, to forge
 * packets able to expire an hop before the destination IP addres, and inject in the
 * stream some valid TCP RSQ, TCP FIN and fake sequenced packet.
 *
 * the other kind of attack work forging packets with bad details, wishing the sniffer ignore
 * those irregularity and poison the connection tracking: injection of RST with bad checksum;
 * bad checksum FIN packet; bad checksum fake SEQ; valid reset with bad sequence number ...
 *
 */
void TCPTrack::inject_hack_in_queue(const Packet &pkt, const SessionTrack *session)
{
	Packet *injpkt;

	/* 
	 * for each kind of packet I apply different hacks. Not every hacks is applied:
	 * some kind of modification cause CWND degrade, for this reason the percentage
	 * requested is < 15, and other hacks with sure effect and less drowback are
	 * ~ 95%
	 */
	struct choosen_hack_pool {
		void (TCPTrack::*choosen_hack)(Packet &);
		/* percentage to be PRESCRIPTION (ttl expire), 
		 * otherwise is GUILTY (invalid packet). 0 mean to be 
		 * INNOCENT (valid packet) 
		 *
		 * WARNING: before stable sniffjoke 1.0, the precentage is 95% because 
		 * bad checksum cause, in TCP congestion algorithm, to decrase CWND
		 *
		 * */
		const char *debug_info;
		int resize;
		/* otherwise, the size is 0 for non-payload-pkt, or a new size required 
		 * by the choosen hack
		 */
		int prcnt;
	} chackpkto[MAXHACKS];

	int hpool_len = 0;
	const int payload_len = ntohs(pkt.ip->tot_len) - ((pkt.ip->ihl * 4) + (pkt.tcp->doff * 4));

	if (runcopy->SjH__shift_ack) {
		
		/* SHIFT ack */
		if (pkt.tcp->ack) {
			if (percentage (logarithm (session->packet_number), 15)) {
				chackpkto[hpool_len].choosen_hack = &TCPTrack::SjH__shift_ack;
				chackpkto[hpool_len].prcnt = 0;
				chackpkto[hpool_len].debug_info =  (char *)"shift ack";
				chackpkto[hpool_len].resize = UNCHANGED_SIZE;
				
				hpool_len++;
				if (hpool_len == MAXHACKS) goto sendchosenhacks; 
			}
		}
	}

	if (runcopy->SjH__fake_data) {

		/* fake DATA injection in stream */

		if (payload_len) {
			if (percentage (logarithm (session->packet_number), 10)) {
				chackpkto[hpool_len].choosen_hack = &TCPTrack::SjH__fake_data;
				chackpkto[hpool_len].prcnt = 98;
				chackpkto[hpool_len].debug_info = (char *)"fake data";
				chackpkto[hpool_len].resize = UNCHANGED_SIZE; 
				
				if (++hpool_len == MAXHACKS) goto sendchosenhacks; 
			}

		}
	}

	if (runcopy->SjH__fake_seq) {
		
		/* fake SEQ injection */
		if (percentage (logarithm (session->packet_number), 15)) {
			chackpkto[hpool_len].choosen_hack = &TCPTrack::SjH__fake_seq;
			chackpkto[hpool_len].prcnt = 98;
			chackpkto[hpool_len].debug_info = (char *)"fake seq";

			if (payload_len > 312)
				chackpkto[hpool_len].resize = (random() % 200);
			else
				chackpkto[hpool_len].resize = UNCHANGED_SIZE;

			if (++hpool_len == MAXHACKS) goto sendchosenhacks; 
		}
	}

	if (runcopy->SjH__fake_close) {
		
		/* fake close (FIN/RST) injection, is required a good ack_seq */
		if (pkt.tcp->ack) {
			if (percentage (logarithm (session->packet_number), 5)) {
				chackpkto[hpool_len].choosen_hack = &TCPTrack::SjH__fake_close;
				chackpkto[hpool_len].prcnt = 98;
				chackpkto[hpool_len].debug_info = (char *)"fake close";
				chackpkto[hpool_len].resize = 0;
				
				if (++hpool_len == MAXHACKS) goto sendchosenhacks; 
			}
		}
	}
		
	if (runcopy->SjH__zero_window) {
		
		/* zero window, test */
		if (percentage (logarithm (session->packet_number), 3)) {
			chackpkto[hpool_len].choosen_hack = &TCPTrack::SjH__zero_window;
			chackpkto[hpool_len].prcnt = 95;
			chackpkto[hpool_len].debug_info = (char *)"zero window";
			chackpkto[hpool_len].resize = 0;
			
			if (++hpool_len == MAXHACKS) goto sendchosenhacks; 
		}
	
	}

	if (runcopy->SjH__valid_rst_fake_seq) {
		
		/* valid RST with invalid SEQ */
		if (percentage (logarithm (session->packet_number), 8)) {
			chackpkto[hpool_len].choosen_hack = &TCPTrack::SjH__valid_rst_fake_seq;
			chackpkto[hpool_len].prcnt = 0;
			chackpkto[hpool_len].debug_info = (char *)"valid rst fake seq";
			chackpkto[hpool_len].resize = 0;
			
			if (++hpool_len == MAXHACKS) goto sendchosenhacks; 
		}
	}

	if (runcopy->SjH__fake_syn) {
		
		/* fake SYN */
		if (percentage (logarithm (session->packet_number), 11)) {
			chackpkto[hpool_len].choosen_hack = &TCPTrack::SjH__fake_syn;
			chackpkto[hpool_len].prcnt = 94;
			chackpkto[hpool_len].debug_info = (char *)"fake syn";
			chackpkto[hpool_len].resize = 0;
			
			/* if (++hpool_len == MAXHACKS) goto sendchosenhacks; */
			/* this is the last hack, remember this line on reaorder or new hacks add */
		}
	}

sendchosenhacks:

	/* -- FINALLY, SEND THE CHOOSEN PACKET(S) */
	if (hpool_len) {
		judge_t court_word;

		for (int i = 0; i < hpool_len; i++) {
			if (chackpkto[i].prcnt) {
				if (percentage(chackpkto[i].prcnt, 100)) 
					court_word = PRESCRIPTION;
				else 
					court_word = GUILTY;
			}
			else 
				court_word = INNOCENT;

			/*
			 * packet_orphanotropy create the new packet with a length 
			 * regrow (for supply to fake data and ip/tcp options)
			 */
			injpkt = packet_orphanotrophy(pkt, chackpkto[i].resize);

			/* what the fuck do with the packets ? its the Court to choose */
			injpkt->wtf = court_word;

			/* calling finally the first kind of hack in the packet injected */
			(*this.*(chackpkto[i].choosen_hack))(*injpkt);
#ifdef HACKSDEBUG
			internal_log(NULL, HACKS_DEBUG,
						"HACKSDEBUG: [%s] (lo:%d %s:%d #%d) id %u len %d-%d[%d] data %d {%d%d%d%d%d}",
						chackpkto[i].debug_info,
						ntohs(injpkt->tcp->source), 
						inet_ntoa(*((struct in_addr *)&injpkt->ip->daddr)) ,
						ntohs(injpkt->tcp->dest), session->packet_number,
						ntohs(injpkt->ip->id),
						injpkt->orig_pktlen,
						injpkt->pbuf_size, ntohs(injpkt->ip->tot_len),
						ntohs(injpkt->ip->tot_len) - ((injpkt->ip->ihl * 4) + (injpkt->tcp->doff * 4)),
						injpkt->tcp->syn, injpkt->tcp->ack, injpkt->tcp->psh, injpkt->tcp->fin, injpkt->tcp->rst
			);
#endif
		}
	}
}

/* 
 * enque_ttl_probe has not the intelligence to understand if TTL bruteforcing 
 * is required or not more. Is called in different section of code
 */
void TCPTrack::enque_ttl_probe(const Packet &delayed_syn_pkt, TTLFocus& ttlfocus)
{
	unsigned char tested_ttl;
	/* 
	 * the first packet (the SYN) is used as starting point
	 * in the enque_ttl_burst to generate the series of 
	 * packets able to detect the number of hop distance 
	 * between our peer and the remote peer. the packet
	 * is lighty modify (ip->id change) and checksum fixed
	 */
	Packet *injpkt;

	if (analyze_ttl_stats(ttlfocus))
		return;

	/* create a new packet
	 * the copy is done to keep refsyn ORIGINAL */
	injpkt = new Packet(delayed_syn_pkt);
	injpkt->proto = TCP;
	injpkt->source = TTLBFORCE;
	injpkt->status = SEND;

	/* 
	 * if TTL expire and is generated and ICMP TIME EXCEEDED,
	 * the iphdr is preserved and the tested_ttl found
	 */
	ttlfocus.sent_probe++;
	tested_ttl = ttlfocus.sent_probe;
	injpkt->ip->ttl = tested_ttl;
	injpkt->tcp->source = ttlfocus.puppet_port;
	injpkt->tcp->seq = htonl(ttlfocus.rand_key + tested_ttl);
	injpkt->ip->id = (ttlfocus.rand_key % 64) + tested_ttl;

	injpkt->fixIpTcpSum();

	p_queue.insert(HIGH, *injpkt);

#ifdef PACKETDEBUG
	internal_log(NULL, PACKETS_DEBUG,
				"Injecting probe %d, tested_ttl %d [exp %d min work %d], (dport %d sport %d) daddr %s",
				ttlfocus.sent_probe,
				tested_ttl, 
				ttlfocus.expiring_ttl, ttlfocus.min_working_ttl, 
				ntohs(injpkt->tcp->dest), ntohs(injpkt->tcp->source),
				inet_ntoa(*((struct in_addr *)&injpkt->ip->daddr))
	);
#endif
}

bool TCPTrack::analyze_ttl_stats(TTLFocus &ttlfocus)
{
	if (ttlfocus.sent_probe == maxttlprobe) {
		ttlfocus.status = TTL_UNKNOW;
		return true;
	}
	return false;
}

void TCPTrack::mark_real_syn_packets_SEND(unsigned int daddr) {

	Packet *packet = p_queue.get(ANY_STATUS, ANY_SOURCE, TCP, false);
	while (packet != NULL) {
		if (packet->tcp->syn && packet->ip->daddr == daddr) {
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG, "The REAL SYN change status from KEEP to SEND");
#endif
			packet->status = SEND;
		}
		packet = p_queue.get(ANY_STATUS, ANY_SOURCE, TCP, true);
	}
}

bool TCPTrack::check_uncommon_tcpopt(const struct tcphdr *tcp)
{
	unsigned char check;
	for (int i = sizeof(struct tcphdr); i < (tcp->doff * 4); i++) {
		check = ((unsigned char *)tcp)[i];

		switch(check) {
			case TCPOPT_TIMESTAMP:
				i += (TCPOLEN_TIMESTAMP +1);
				break;
			case TCPOPT_EOL:
			case TCPOPT_NOP:
				break;
			case TCPOPT_MAXSEG:
			case TCPOPT_WINDOW:
			case TCPOPT_SACK_PERMITTED:
			case TCPOPT_SACK:
				return true;
			default:
				return true;
		}
	}
	return false;
}

/* packet orphanotrophy, create the oraphans packet and raise them correctly */
Packet* TCPTrack::packet_orphanotrophy(const Packet &pkt, int resize)
{
	Packet *ret = new Packet(pkt);
	ret->proto = TCP;
	ret->source = LOCAL;
	ret->status = SEND;

	/* 
	 * the packets generated could be resized, for the sniffjoke hack
	 */
	switch(resize) {
		case UNCHANGED_SIZE:
			break;
		default:
			ret->resizePayload(resize);
	}
	
	p_queue.insert(HIGH, *ret);
	
	return ret;
}


/* 
 * this two functions is required on hacking injection, because that 
 * injection should happens ALWAYS, but give the less possible elements
 * to the attacker for detects sniffjoke working style
 */
bool TCPTrack::percentage(float math_choosed, int vecna_choosed)
{
	return ((random() % 100) <= ((int)(math_choosed * vecna_choosed) / 100));
}

/*  the variable is used from the sniffjoke routing for decreete the possibility of
 *  an hack happens. this variable are mixed in probabiliy with the session->packet_number, because
 *  the hacks must happens, for the most, in the start of the session (the first 10 packets),
 *  other hacks injection should happen in the randomic mode express in logarithm function.
 */
float TCPTrack::logarithm(int packet_number)
{
	int blah;

	if (packet_number < 20)
		return 150.9;

	if (packet_number > 10000)
		blah = (packet_number / 10000) * 10000;
	else if (packet_number > 1000)
		blah = (packet_number / 1000) * 1000;
	else if (packet_number > 100)
		blah = (packet_number / 100) * 100;
	else
		return 2.2; /* x > 8 && x < 100 */

	if (blah == packet_number)
		return 90.0;
	else
		return 0.08;
}

SessionTrack* TCPTrack::init_sessiontrack(const Packet &pkt) 
{
	/* pkt is the refsyn, SYN packet reference for starting ttl bruteforce */
	SessionTrack *session = sex_list.get(pkt);
	if (session == NULL) {
		session = new SessionTrack(pkt);
		sex_list.push_back(*(session));
	}
	
	return session;
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
 * TCP/IP hacks, focus:
 *
 *  suppose the sniffer reconstruction flow, suppose which variable they use, make them
 *  variables fake and send a packet that don't ruin the real flow.
 *
 * SjH__ = sniffjoke hack
 *
 */
void TCPTrack::SjH__fake_data(Packet &hackpkt)
{
	const int diff = ntohs(hackpkt.ip->tot_len) - ((hackpkt.ip->ihl * 4) + (hackpkt.tcp->doff * 4));

	hackpkt.ip->id = htons(ntohs(hackpkt.ip->id) + (random() % 10));

	for (int i = 0; i < diff - 3; i += 4)
		*(long int *)&(hackpkt.payload[i]) = random();
}

void TCPTrack::SjH__fake_seq(Packet &hackpkt)
{
	int what = (random() % 3);

	/* 
	 * MAXOPTINJ is used * 3 because the packet can be incremented in size here,
	 * have ipopt and tcpopt. This variable should, and is better if became random
	 * instead of fixed value.
	 */
	if (!hackpkt.payload) {
		hackpkt.tcp->seq = htonl(ntohl(hackpkt.tcp->seq) + MAXOPTINJ * 3);
		hackpkt.ip->tot_len = htons(ntohs(hackpkt.ip->tot_len) + MAXOPTINJ * 3);
	} else
		if (what == 0)
			what = 2;

	if (what == 2) 
		hackpkt.tcp->seq = htonl(ntohl(hackpkt.tcp->seq) + (random() % 5000));

	else /* what == 1 */
		hackpkt.tcp->seq = htonl(ntohl(hackpkt.tcp->seq) - (random() % 5000));

	hackpkt.tcp->window = htons((random() % 80) * 64);
	hackpkt.tcp->ack = 0;
	hackpkt.tcp->ack_seq = 0;

	SjH__fake_data(hackpkt);
}

/* fake syn, same more or less value, but, fake */
void TCPTrack::SjH__fake_syn(Packet &hackpkt)
{
	hackpkt.tcp->psh = 0;
	hackpkt.tcp->syn = 1;

	hackpkt.ip->id = htons(ntohs(hackpkt.ip->id) + (random() % 10));
	hackpkt.tcp->seq = htonl(ntohl(hackpkt.tcp->seq) + 65535 + (random() % 5000));

	/* 20% is a SYN ACK */
	if ((random() % 5) == 0) {
		hackpkt.tcp->ack = 1;
		hackpkt.tcp->ack_seq = htonl(random());
	} else {
		hackpkt.tcp->ack = 0;
		hackpkt.tcp->ack_seq = 0;
	}

	/* payload is always truncated */
	hackpkt.ip->tot_len = htons((hackpkt.ip->ihl * 4) + (hackpkt.tcp->doff * 4));

	/* 20% had source and dest port reversed */
	if ((random() % 5) == 0) {
		unsigned short swap = hackpkt.tcp->source;
		hackpkt.tcp->source = hackpkt.tcp->dest;
		hackpkt.tcp->dest = swap;
	}
}

void TCPTrack::SjH__fake_close(Packet &hackpkt)
{
	const int original_size = hackpkt.orig_pktlen - (hackpkt.ip->ihl * 4) - (hackpkt.tcp->doff * 4);
	hackpkt.ip->id = htons(ntohs(hackpkt.ip->id) + (random() % 10));
	
	/* fake close could have FIN+ACK or RST+ACK */
	hackpkt.tcp->psh = 0;

	if (1) /* if (random() % 2) FIXME, a fake rst seems to break connection */
		hackpkt.tcp->fin = 1;
	else
		hackpkt.tcp->rst = 1; 

	/* in both case, the sequence number must be shrink as no data are there.
	 * the ack_seq is set because the ACK flag is checked to be 1 */
	hackpkt.tcp->seq = htonl(ntohl(hackpkt.tcp->seq) - original_size + 1);
}

void TCPTrack::SjH__zero_window(Packet &hackpkt)
{
	hackpkt.tcp->syn = hackpkt.tcp->fin = hackpkt.tcp->rst = 1;
	hackpkt.tcp->psh = hackpkt.tcp->ack = 0;
	hackpkt.tcp->window = 0;
}

void TCPTrack::SjH__shift_ack(Packet &hackpkt)
{
	hackpkt.ip->id = htons(ntohs(hackpkt.ip->id) + (random() % 10));
	hackpkt.tcp->ack_seq = htonl(ntohl(hackpkt.tcp->ack_seq) + 65535);
}

void TCPTrack::SjH__valid_rst_fake_seq(Packet &hackpkt)
{
	/* 
	 * if the session is resetted, the remote box maybe vulnerable to:
	 * Slipping in the window: TCP Reset attacks
	 * http://kerneltrap.org/node/3072
	 */
	hackpkt.ip->id = htons(ntohs(hackpkt.ip->id) + (random() % 10));
	hackpkt.tcp->seq = htonl(ntohl(hackpkt.tcp->seq) + 65535 + (random() % 12345));
	hackpkt.tcp->window = (unsigned short)(-1);
	hackpkt.tcp->rst = hackpkt.tcp->ack = 1;
	hackpkt.tcp->ack_seq = htonl(ntohl(hackpkt.tcp->seq + 1));
	hackpkt.tcp->fin = hackpkt.tcp->psh = hackpkt.tcp->syn = 0;
}

/* ipopt IPOPT_RR inj*/
void TCPTrack::SjH__inject_ipopt(Packet &hackpkt)
{
	int iphlen = hackpkt.ip->ihl * 4;
	int tcphlen = hackpkt.tcp->doff * 4;
	const int l47len = ntohs(hackpkt.ip->tot_len) - iphlen;
	const int max_route_n = (hackpkt.pbuf_size - ntohs(hackpkt.ip->tot_len)) / 4 - 1;
	const int route_n = max_route_n > 9 ? (random() % 10) : max_route_n;
	
	const unsigned fakeipopt = ((route_n + 1) * 4);
	unsigned char *endip = hackpkt.pbuf + sizeof(struct iphdr);
	const int startipopt = hackpkt.ip->ihl * 4 - sizeof(struct iphdr);

	/* 1: strip the original ip options, if present, copying payload over */	
	if (iphlen > sizeof(struct iphdr)) 
		memmove(endip, endip + startipopt, l47len);

	iphlen = sizeof(struct iphdr) + fakeipopt;

	/* 2: shift the tcphdr and the payload bytes after the reserved space to IPOPT_RR */
	memmove(endip + fakeipopt, endip, l47len);

	endip[0] = IPOPT_NOP;
	endip[1] = IPOPT_RR;		/* IPOPT_OPTVAL */
	
	/* Here comes the tha hack, 4 more or 4 less the right value*/
	if (random() % 2)
		endip[2] = fakeipopt - 1 - (4 * (random() % 5));	/* IPOPT_OLEN   */
	else
		endip[2] = fakeipopt - 1 + (4 * (random() % 5));	/* IPOPT_OLEN   */
				
	endip[3] = IPOPT_MINOFF;	/* IPOPT_OFFSET = IPOPT_MINOFF = 4 */


	for (int i = 4; i < fakeipopt; i++)
		endip[i] = (char)random();

#ifdef HACKSDEBUG
	internal_log(NULL, HACKS_DEBUG,
				"HACKSDEBUG [Inj IpOpt] (lo:%d %s:%d) (route_n %d) id %u l47 %d tot_len %d -> %d {%d%d%d%d%d}",
				ntohs(hackpkt.tcp->source), 
				inet_ntoa(*((struct in_addr *)&hackpkt.ip->daddr)) ,
				ntohs(hackpkt.tcp->dest), 
				route_n,
				ntohs(hackpkt.ip->id),
				l47len,
				ntohs(hackpkt.ip->tot_len),
				(iphlen + l47len),
				hackpkt.tcp->syn, hackpkt.tcp->ack, hackpkt.tcp->psh, hackpkt.tcp->fin, hackpkt.tcp->rst
	);
#endif

	hackpkt.ip->ihl = iphlen / 4;
	hackpkt.ip->tot_len = htons(iphlen + l47len);
	hackpkt.tcp = (struct tcphdr *)((unsigned char*)(hackpkt.ip) + iphlen);
	hackpkt.payload = (unsigned char *)(hackpkt.tcp) + tcphlen;
}


/* tcpopt TCPOPT_TIMESTAMP inj with bad TCPOLEN_TIMESTAMP */
void TCPTrack::SjH__inject_tcpopt(Packet &hackpkt) 
{
	int iphlen = hackpkt.ip->ihl * 4;
	int tcphlen = hackpkt.tcp->doff * 4;
	const int l57len = ntohs(hackpkt.ip->tot_len) - (iphlen + tcphlen);
	const int faketcpopt = 8;
	unsigned char *endtcp = hackpkt.pbuf + iphlen + sizeof(struct tcphdr);
	const int starttcpopt = tcphlen - sizeof(struct tcphdr);
	const time_t now = time(NULL);

	/* 1: strip the original tcp options, if present, copying payload over */
	if (tcphlen > sizeof(struct tcphdr))
		memmove(endtcp, endtcp + starttcpopt, l57len);

	tcphlen = sizeof(struct tcphdr) + faketcpopt;
	
	/* 2: shift the payload after the reserved space to faketcpopt */
	memmove(endtcp + faketcpopt, endtcp, l57len);

	endtcp[0] = TCPOPT_NOP;
	endtcp[1] = TCPOPT_NOP;
	endtcp[2] = TCPOPT_TIMESTAMP;
	endtcp[3] = 6;

	/*  6 is an invalid value;
	 *  from: /usr/include/netinet/tcp.h:
	 *  # define TCPOLEN_TIMESTAMP	  10
	 */

	/* time_t, 4 byte of time stamp value */
	memcpy(&endtcp[4], &now, sizeof(time_t));

#ifdef HACKSDEBUG
	internal_log(NULL, HACKS_DEBUG,
				"HACKSDEBUG [Fake TcpOpt] (lo:%d %s:%d) id %u l57 %d tot_len %d -> %d {%d%d%d%d%d}",
				ntohs(hackpkt.tcp->source), 
				inet_ntoa(*((struct in_addr *)&hackpkt.ip->daddr)) ,
				ntohs(hackpkt.tcp->dest), 
				ntohs(hackpkt.ip->id),
				l57len,
				ntohs(hackpkt.ip->tot_len),
				(iphlen + tcphlen + faketcpopt + l57len),
				hackpkt.tcp->syn, hackpkt.tcp->ack, hackpkt.tcp->psh, hackpkt.tcp->fin, hackpkt.tcp->rst
	);
#endif
	hackpkt.ip->tot_len = htons(iphlen + tcphlen + faketcpopt + l57len);
	hackpkt.tcp->doff = (sizeof(struct tcphdr) + 2) & 0xf;
	hackpkt.payload = (unsigned char *)(hackpkt.tcp) + tcphlen;
}
