/*
 * SniffJoke project: this is the file most edited
 * http://www.delirandom.net/sniffjoke, this file in G's codesearch:
 * http://www.delirandom.net/sniffjoke/sniffjoke-0.3/sniffjoke-src/TCPTrack.cc
 */

#include <iostream>
#include <cerrno>
using namespace std;
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include "SjUtils.h"
#include "TCPTrack.h"

// define PACKETDEBUG enable session debug, ttl bruteforce 
#define PACKETDEBUG 
// define HACKSDEBUG enable dump about packet injected
#define HACKSDEBUG

#define DATADEBUG // WARNING: if you #define DATADEBUG, you need to mkdir /tmp/datadump
#ifdef DATADEBUG
#include "Optional_DataDebug.h"
static DataDebug *dd;
#endif

TCPTrack::TCPTrack(SjConf *sjconf) 
{
	int i;

	runcopy = sjconf->running;

	sextraxmax = runcopy->max_session_tracked;
	paxmax = runcopy->max_packet_que;
	maxttlfocus = runcopy->max_tracked_ttl;
	maxttlprobe = runcopy->max_ttl_probe;

	sex_list = (struct sniffjoke_track *)calloc( sextraxmax, sizeof(struct sniffjoke_track) );
	pblock_list = (struct packetblock *)calloc( paxmax, sizeof(struct packetblock) );
	ttlfocus_list = (struct ttlfocus *)calloc( maxttlfocus, sizeof(struct ttlfocus) );

	if(sex_list == NULL || pblock_list == NULL || ttlfocus_list == NULL) {
		internal_log(NULL, ALL_LEVEL, "unable to alloc TCPTrack.cc constructor lists");
		check_call_ret("memory allocation", errno, -1, true);
	}

	/* init the counter to 0 */
	sex_list_count[0] = sex_list_count[1] = 0;
	pblock_list_count[0] = pblock_list_count[1] = 0;

	/* random pool initialization */
	for( i = 0; i < ( (random() % 40) + 3 ); i++ ) 
		srandom( (unsigned int)time(NULL) ^ random() );

#ifdef DATADEBUG
	dd = new DataDebug( );
	dd->session_tracked = runcopy->max_session_tracked;
	dd->packet_queue = runcopy->max_packet_que;
	dd->tracked_ttl = runcopy->max_tracked_ttl;
	dd->Session = sex_list;
	dd->Packet = pblock_list;
	dd->TTL = ttlfocus_list;
#endif

	internal_log(NULL, DEBUG_LEVEL, "TCPTrack.cc initialized object: list %d packets %d ttl %d", sextraxmax, paxmax, maxttlfocus);
}

TCPTrack::~TCPTrack() 
{
	internal_log(NULL, ALL_LEVEL, "~TCPTrack: freeing %d session list, %d packet queue, %d tracked ttl",
		sextraxmax, paxmax, maxttlfocus
	);

	if(sex_list != NULL)
		free(sex_list);

	if(pblock_list != NULL)
		free(pblock_list);

	if(ttlfocus_list != NULL)
		free(ttlfocus_list);

#ifdef DATADEBUG
	if(dd != NULL) {
		delete dd;
		dd = NULL;
	}
#endif
}

bool TCPTrack::check_evil_packet( const unsigned char * buff, int nbyte)
{
	struct iphdr *ip;
		
	ip = (struct iphdr *)buff;
 
	if( nbyte < sizeof(struct iphdr) || nbyte != ntohs(ip->tot_len) ) {
#ifdef DATADEBUG
		dd->InfoMsg("Packet", "check_evil_packet: if( nbyte < sizeof(struct iphdr) || nbyte < ntohs(ip->tot_len) )");
#endif
		return false;
	}

	if(ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp;
		int iphlen;
		int tcphlen;

		iphlen = ip->ihl * 4;

		if(nbyte < iphlen + sizeof(struct tcphdr) ) {
#ifdef DATADEBUG
			dd->InfoMsg("Packet", "check_evil_packet: if( nbyte < iphlen + sizeof(struct tcphdr) )");
#endif
			return false;
		}

		tcp = (struct tcphdr *)((unsigned char *)ip + iphlen);
		tcphlen = tcp->doff * 4;
		
		if( ntohs(ip->tot_len) < iphlen + tcphlen ) {
#ifdef DATADEBUG
			dd->InfoMsg("Packet", "check_evil_packet: if( ntohs(ip->tot_len) < iphlen + tcphlen )");
#endif
			return false;
		}
	}
	
	return true;
}

/* the packet is add in the packet queue for be analyzed in a second time */
void TCPTrack::add_packet_queue( const source_t source, const unsigned char *buff, int nbyte )
{
	struct packetblock *target;
	unsigned int packet_id = make_pkt_id( buff );

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
#ifdef DATADEBUG
	dd->InfoMsg("Packet", "add_packet_queue: Requested LOW packet: Sj_packet_id %8x (length %d byte)", packet_id, nbyte);
#endif
	target = get_free_pblock( nbyte + (MAXOPTINJ * 3), LOW, packet_id );

	target->packet_id = packet_id;
	target->source = source;
	target->status = YOUNG;
	target->wtf = INNOCENT;
	target->orig_pktlen = nbyte;

	memcpy(target->pbuf, buff, nbyte);
	
	update_pblock_pointers( target );
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
	struct packetblock *newp;
	struct sniffjoke_track *ct;

#ifdef DATADEBUG
	dd->InfoMsg("Packet", "analyze_packets_queue");
	dd->Dump_Packet( paxmax );
#endif

	newp = get_pblock(YOUNG, NETWORK, ICMP, false);
	while ( newp != NULL )
	{
		/* 
 		 * a TIME_EXCEEDED packet should contains informations
 		 * for discern HOP distance from a remote host
 		 */
		if(newp->icmp->type == ICMP_TIME_EXCEEDED) 
			analyze_incoming_icmp(newp);

		/* if packet exist again = is not destroyed by analyze function */
		if(newp != NULL)
			newp->status = SEND;
		
		newp = get_pblock(YOUNG, NETWORK, ICMP, true);
	}

	/* 
 	 * incoming TCP. sniffjoke algorithm open/close sessions and detect TTL
 	 * lists analyzing SYN+ACK and FIN|RST packet
 	 */
 	newp = get_pblock(YOUNG, NETWORK, TCP, false);
	while ( newp != NULL ) 
	{
		if(newp->tcp->syn && newp->tcp->ack)
			analyze_incoming_synack(newp);

		if(newp->status == YOUNG && (newp->tcp->rst || newp->tcp->fin))
			analyze_incoming_rstfin(newp);	

		/* if packet exist again = is not destroyed by analyze function */
		if(newp != NULL)
			newp->status = SEND;
			
		newp = get_pblock(YOUNG, NETWORK, TCP, true);
	}

	/* outgoing TCP packets ! */
	newp = get_pblock(YOUNG, TUNNEL, TCP, false);
	while ( newp != NULL )
	{
		unsigned short destport = ntohs(newp->tcp->dest);

		/* no hacks required for this destination port */
		if(runcopy->portconf[destport] == NONE) {
			newp->status = SEND; 
			continue;
		}

		/* 
 		 * create/close session, check ttlfocus and start new discovery, 
 		 * this function contains the core functions of sniffjoke: 
 		 * enque_ttl_probe and inject_hack_in_queue 
 		 *
 		 * those packets had ttlfocus set inside
 		 */
		manage_outgoing_packets(newp);

		/* all outgoing packets, exception for starting SYN (status = KEEP), are sent immediatly */
		if(newp != NULL && newp->status != KEEP)
			newp->status = SEND;
			
		newp = get_pblock(YOUNG, TUNNEL, TCP, true);
	}

	int i = 0;
	newp = get_pblock(KEEP, TUNNEL, TCP, false);
	while ( newp != NULL ) 
	{
		ct = find_sexion( newp );

		if(ct->tf->status == TTL_BRUTALFORCE) 
		{
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG, "status BRUTALFORCE for %s: %d %d pkt is KEEP (%d), send probe %d rcvd %d probe",
				inet_ntoa( *((struct in_addr *)&ct->tf->daddr) ) ,
				ntohs(newp->tcp->source), 
				ntohs(newp->tcp->dest),
				ct->tf->status, ct->tf->sent_probe, ct->tf->received_probe
			);
#endif
			enque_ttl_probe( newp, ct );
		}
		newp = get_pblock(KEEP, TUNNEL, TCP, true);
	}

	/* all others YOUNG packets must be send immediatly */
	newp = get_pblock(YOUNG, ANY_SOURCE, ANY_PROTO, false);
	while ( newp != NULL ) 
	{
		newp->status = SEND;
		newp = get_pblock(YOUNG, ANY_SOURCE, ANY_PROTO, true);
	}
}

struct packetblock * TCPTrack::get_pblock(status_t status, source_t source, proto_t proto, bool must_continue) 
{
	static int start_index = 0;
	int i;

	if (!must_continue)
		start_index = 0;

	for(i = start_index; i < paxmax; i++) 
	{
		if (status != ANY_STATUS && pblock_list[i].status != status )
			continue;

		if (source != ANY_SOURCE && pblock_list[i].source != source )
			continue;

		if (proto != ANY_PROTO && pblock_list[i].proto != proto )
			continue;

		update_pblock_pointers( &pblock_list[i] );
		
		start_index = i + 1;
		return &(pblock_list[i]);
	}

	return NULL;
}

void TCPTrack::clear_pblock( struct packetblock *used_pb )
{
	int i;
	int free = 1;

	for(i = 0; i < paxmax; i++) 
	{		
		if( &(pblock_list[i]) == used_pb ) 
		{
			memset(used_pb, 0x00, sizeof(struct packetblock));
			
			if ( i < paxmax /2 ) {
				pblock_list_count[0]--;
				if (pblock_list_count[0] == 0)
					recompact_pblock_list(0);
			} else {
				pblock_list_count[1]--;
				if (pblock_list_count[1] == 0)
					recompact_pblock_list(1);
			}
				
			return;
		}
	}
		
	check_call_ret("unforeseen bug: TCPTrack.cc, contact the sofware manteiner, sorry. function clear_pblock", 0, -1, true);
}


void TCPTrack::update_pblock_pointers( struct packetblock *pb ) {

	pb->ip = (struct iphdr *)pb->pbuf;

	if(pb->ip->protocol == IPPROTO_TCP) {
		pb->proto = TCP;
		pb->tcp = (struct tcphdr *)((unsigned char *)(pb->ip) + (pb->ip->ihl * 4));
		pb->icmp = NULL;
		pb->payload = (unsigned char *)pb->tcp + pb->tcp->doff * 4;
	} else if (pb->ip->protocol == IPPROTO_ICMP) {
		pb->proto = ICMP;
		pb->tcp = NULL;
		pb->icmp = (struct icmphdr *)((unsigned char *)(pb->ip) + (pb->ip->ihl * 4));
		pb->payload = NULL;
	} else {
		pb->proto = OTHER_IP;
		pb->tcp = NULL;
		pb->icmp = NULL;
		pb->payload = NULL;
	}
}

/*
 * this function set SEND stats to all packets, is used when sniffjoke must not 
 * mangle the packets 
 */
void TCPTrack::force_send()
{
	int i;

#ifdef PACKETDEBUG
	int counter =0;
#endif

	for(i = 0; i < paxmax; i++) {
		if(pblock_list[i].pbuf_size) {
#ifdef PACKETDEBUG
			counter++;
#endif
			pblock_list[i].status = SEND;
		}
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
void TCPTrack::last_pkt_fix( struct packetblock *pkt )
{
#define STARTING_ARB_TTL 46
	time_t now = time(NULL);
	int i;

	/* 
	 * packets different from TCP, and packets without ttl focus struct are
	 * send immediatly
	 */ 
#ifdef PACKETDEBUG
	if(pkt->proto == TCP) 
		internal_log(NULL, PACKETS_DEBUG,
			"last_pkt_fix (TCP) : id %u (lo:%d %s:%d) proto %d source %d", 
			ntohs(pkt->ip->id), 
			ntohs(pkt->tcp->source),
			inet_ntoa( *((struct in_addr *)&pkt->ip->daddr) ) ,
			ntohs(pkt->tcp->dest), 
			pkt->ip->protocol, 
			pkt->source
		);
	else 
		internal_log(NULL, PACKETS_DEBUG,
			"last_pkt_fix (!TCP): id %u proto %d source %d", 
			ntohs(pkt->ip->id), 
			pkt->ip->protocol, 
			pkt->source
		);
#endif

	if(pkt->proto != TCP || pkt->tf == NULL)
		return;

	/* 1st check: HOW MANY TTL GIVE TO THE PACKET ? */
	if(pkt->tf->status == TTL_UNKNOW) 
	{
		if(pkt->wtf == PRESCRIPTION)
			pkt->wtf = GUILTY;

		pkt->ip->ttl = STARTING_ARB_TTL + (random() % 20);
	}
	else 
	{
		if(pkt->wtf == PRESCRIPTION) 
			pkt->ip->ttl = pkt->tf->expiring_ttl; 
		else 	/* GUILTY or INNOCENT */
			pkt->ip->ttl = (pkt->tf->expiring_ttl + (random() % 5) + 1 );
	}

	/* 
	 * 2nd check: HOW MANY IP/TCP OPTIONS SET TO THE PACKET ?, the pbuf_size is
 	 * ready with "int variable_iptcpopt = (MAXOPTINJ * 3);" byte, in 
 	 * packet_orphanotrophy.
 	 */
	if (!pkt->tcp->syn) { 
		
		if( runcopy->SjH__inject_ipopt ) {
			if ( ntohs(pkt->ip->tot_len) < (MTU - 72) )
				if( percentage( 1, 100 ) )
					SjH__inject_ipopt( pkt );
		}

		if( runcopy->SjH__inject_tcpopt ) {
			if ( !check_uncommon_tcpopt(pkt->tcp) && pkt->wtf != INNOCENT )
				if( percentage( 25, 100 ) )
					SjH__inject_tcpopt( pkt );
		}
	}

	/* 3rd check: GOOD CHECKSUM or BAD CHECKSUM ? */
	fix_iptcp_sum(pkt->ip, pkt->tcp);

	if(pkt->wtf == GUILTY)
		pkt->tcp->check ^= (0xd34d * (unsigned short)random() +1);
}


void TCPTrack::analyze_incoming_icmp( struct packetblock *timeexc )
{
	struct iphdr *badiph;
	struct tcphdr *badtcph;
	struct ttlfocus *tf;

	badiph = (struct iphdr *)((unsigned char *)timeexc->icmp + sizeof(struct icmphdr));
	badtcph = (struct tcphdr *)((unsigned char *)badiph + (badiph->ihl * 4));

#ifdef DATADEBUG
	dd->InfoMsg("TTL", "analyze_incoming_icmp");
	dd->Dump_TTL( maxttlfocus );
#endif
	tf = find_ttl_focus(badiph->daddr, 0);

	if(tf != NULL && badiph->protocol == IPPROTO_TCP) 
	{
		unsigned char expired_ttl = badiph->id - (tf->rand_key % 64);
		unsigned char exp_double_check = ntohl(badtcph->seq) - tf->rand_key;

		if(tf->status != TTL_KNOW && expired_ttl == exp_double_check ) 
		{
			tf->received_probe++;

			if( expired_ttl > tf->expiring_ttl) {
#ifdef PACKETDEBUG
				internal_log(NULL, PACKETS_DEBUG, "TTL OK: (sent %d recvd %d) previous %d now %d", 
					tf->sent_probe, tf->received_probe,
					tf->expiring_ttl, expired_ttl
				);
#endif
				tf->expiring_ttl = expired_ttl;
			}
#ifdef PACKETDEBUG
			else {
				internal_log(NULL, PACKETS_DEBUG, "TTL BAD: (sent %d recvd %d) previous %d now %d",
					tf->sent_probe, tf->received_probe,
					tf->expiring_ttl, expired_ttl
				);
			}
#endif
		}
		clear_pblock(timeexc);
		timeexc = NULL;
	}
}

void TCPTrack::analyze_incoming_synack( struct packetblock *synack )
{
	struct ttlfocus *tf;

#ifdef DATADEBUG
	dd->InfoMsg("Session", "analyzie_incoming_synack, from: %s", inet_ntoa( *((struct in_addr *)&synack->ip->saddr) ));
	dd->Dump_Session ( sextraxmax );
#endif

	/* NETWORK is src: dest port and source port inverted and saddr are used, 
 	 * source is put as last argument (puppet port)
	 */
	if((tf = find_ttl_focus( synack->ip->saddr, 0)) == NULL) 
		return;

#ifdef PACKETDEBUG
	internal_log(NULL, PACKETS_DEBUG, "SYN/ACK (saddr %u) seq %08x seq_ack %08x - dport %d sport %d puppet %d",
		synack->ip->saddr,
		ntohl(synack->tcp->seq),
		ntohl(synack->tcp->ack_seq),
		ntohs(synack->tcp->dest), 
		ntohs(synack->tcp->source),
		ntohs(tf->puppet_port)
	);
#endif

	if ( synack->tcp->dest == tf->puppet_port )
	{
		unsigned char discern_ttl;

		tf->received_probe++;
		discern_ttl =  ntohl(synack->tcp->ack_seq) - tf->rand_key -1;
		tf->status = TTL_KNOW;

#ifdef PACKETDEBUG
		internal_log(NULL, PACKETS_DEBUG,
			"discern_ttl %d: min working ttl %d expiring ttl %d recv probe %d sent probe %d",
			discern_ttl,
			tf->min_working_ttl,
			tf->expiring_ttl,
			tf->received_probe,
			tf->sent_probe
		);
#endif

		if(tf->min_working_ttl > discern_ttl && discern_ttl <= tf->sent_probe) 
			tf->min_working_ttl = discern_ttl;

		/* 
 		 * this code flow happens only when the SYN ACK is received, due to
 		 * a SYN send from the "puppet port". this kind of SYN is used only
 		 * for discern TTL, and this mean a REFerence-SYN packet is present in
 		 * the packet queue. Now that ttl has been detected, the real SYN could
 		 * be send.
		 */
		
		mark_real_syn_packets_SEND( synack->ip->saddr );
		
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

void TCPTrack::analyze_incoming_rstfin( struct packetblock *rstfin )
{
	struct sniffjoke_track *ct;

#ifdef PACKETDEBUG
	internal_log(NULL, PACKETS_DEBUG,
		"RST/FIN received (NET): ack_seq %08x, sport %d dport %d saddr %u",
		rstfin->tcp->ack_seq, 
		ntohs(rstfin->tcp->source),
		ntohs(rstfin->tcp->dest),
		rstfin->ip->saddr
	);
#endif

	ct = get_sexion(rstfin->ip->saddr, rstfin->tcp->dest, rstfin->tcp->source);

	if(ct != NULL) {
		/* 
		 * clear_sexion don't remove conntrack immediatly, at the first call
		 * set the "shutdown" bool variable, at the second clear it, this
		 * because of double FIN-ACK and RST-ACK happening between both hosts.
		 */
		clear_sexion(ct);
	}
}

void TCPTrack::manage_outgoing_packets( struct packetblock *newp )
{
	struct sniffjoke_track *ct;

	/* 
 	 * get_sexion return an existing sexion or even NULL, 
 	 * find_sexion create a new, if required 
 	 */
	if(newp->tcp->syn) 
	{
		ct = find_sexion( newp );
#ifdef PACKETDEBUG
		internal_log(NULL, PACKETS_DEBUG,
			"SYN from TUNNEL:%d %s:%d",
			ntohs(newp->tcp->source),
			inet_ntoa( *((struct in_addr *)&newp->ip->daddr) ),
			ntohs(newp->tcp->dest) 
		);
#endif
		/* if sniffjoke had not yet the minimum working ttl, continue the starting probe */
		if(ct->tf->status == TTL_BRUTALFORCE) 
		{
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG, "SYN retransmission - DROPPED");
#endif
			enque_ttl_probe( newp, ct );
			newp->status = KEEP; 
			return;
		}
	}
	
	ct = get_sexion( newp->ip->daddr, newp->tcp->source, newp->tcp->dest);

	if( ct != NULL)
	{
		if (newp->tcp->rst || newp->tcp->fin )
		{
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG,
				"FIN/RST (TUN) clear: seq %08x seq_ack %08x (rst %d fin %d ack %d) dport %d sport %d)",
				ntohl(newp->tcp->seq),
				ntohl(newp->tcp->ack_seq),
				newp->tcp->rst, newp->tcp->fin, 
				newp->tcp->ack,
				ntohs(newp->tcp->dest), ntohs(newp->tcp->source)
			);
#endif
			/* 
			 * clear_sexion don't remove conntrack immediatly, at the first 
			 * invoke set "shutdown" variable, at the second clear it 
			 */
			clear_sexion(ct);
			
			/* a closed or shutdown session don't require to be hacked */
			return;
		}
	} else
		return;

	ct->packet_number++;
	newp->tf = ct->tf;

	/* update_session_stat( xml_stat_root, ct ); */

	inject_hack_in_queue( newp, ct );
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
void TCPTrack::inject_hack_in_queue( struct packetblock *pb, struct sniffjoke_track *ct ) 
{
	struct packetblock *inj;

	/* 
 	 * for each kind of packet I apply different hacks. Not every hacks is applied:
 	 * some kind of modification cause CWND degrade, for this reason the percentage
 	 * requested is < 15, and other hacks with sure effect and less drowback are
 	 * ~ 95%
 	 */
	struct choosen_hack_pool {
		void (TCPTrack::*choosen_hack)(struct packetblock *);
		/* percentage to be PRESCRIPTION (ttl expire), 
 		 * otherwise is GUILTY (invalid packet). 0 mean to be 
 		 * INNOCENT (valid packet) 
 		 *
 		 * WARNING: before stable sniffjoke 1.0, the precentage is 95% because 
 		 * bad checksum cause, in TCP congestion algorithm, to decrase CWND
 		 *
 		 * */
		char *debug_info;
		int resize;
#define UNCHANGED_SIZE	(-1)
		/* otherwise, the size is 0 for non-payload-pkt, or a new size required 
 		 * by the choosen hack
 		 */
		int prcnt;
#define MAX_HACKS_N	7
	} chackpo[MAX_HACKS_N];

	int hpool_len = 0;
	int payload_len = ntohs(pb->ip->tot_len) - ((pb->ip->ihl * 4) + (pb->tcp->doff * 4));

	if (runcopy->SjH__shift_ack) {
		
		/* SHIFT ack */
		if ( pb->tcp->ack ) 
		{
			if ( percentage ( logarithm ( ct->packet_number ), 15 ) ) 
			{
				chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__shift_ack;
				chackpo[hpool_len].prcnt = 0;
				chackpo[hpool_len].debug_info =  (char *)"SHIFT ack";
				chackpo[hpool_len].resize = UNCHANGED_SIZE;
				
				hpool_len++;
				if(hpool_len == MAX_HACKS_N) goto sendchosenhacks; 
			}
		}
	}

	if (runcopy->SjH__fake_data) {

		/* fake DATA injection in stream */

		if ( payload_len ) 
		{
			if ( percentage ( logarithm ( ct->packet_number ), 10 ) ) 
			{
				chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__fake_data;
				chackpo[hpool_len].prcnt = 98;
				chackpo[hpool_len].debug_info = (char *)"fake DATA";
				chackpo[hpool_len].resize = UNCHANGED_SIZE; 
				
				hpool_len++;
				if(hpool_len == MAX_HACKS_N) goto sendchosenhacks; 
			}

		}
	}

	if (runcopy->SjH__fake_seq) {
		
		/* fake SEQ injection */
		if ( percentage ( logarithm ( ct->packet_number ), 15 ) )
		{
			chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__fake_seq;
			chackpo[hpool_len].prcnt = 98;
			chackpo[hpool_len].debug_info = (char *)"fake SEQ";

			if(payload_len > 312)
				chackpo[hpool_len].resize = (random() % 200);
			else
				chackpo[hpool_len].resize = UNCHANGED_SIZE;

			hpool_len++;
			if(hpool_len == MAX_HACKS_N) goto sendchosenhacks; 
		}
	}

	if (runcopy->SjH__fake_close) {
		
		/* fake close (FIN/RST) injection, is required a good ack_seq */
		if ( pb->tcp->ack ) 
		{
			if ( percentage ( logarithm ( ct->packet_number ), 5 ) ) 
			{
				chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__fake_close;
				chackpo[hpool_len].prcnt = 98;
				chackpo[hpool_len].debug_info = (char *)"fake FIN/RST";
				chackpo[hpool_len].resize = 0;
				
				hpool_len++;
				if(hpool_len == MAX_HACKS_N) goto sendchosenhacks; 
			}
		}
	}
		
	if (runcopy->SjH__zero_window) {
		
		/* zero window, test */
		if ( percentage ( logarithm ( ct->packet_number ), 3 ) ) 
		{
			chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__zero_window;
			chackpo[hpool_len].prcnt = 95;
			chackpo[hpool_len].debug_info = (char *)"zero window";
			chackpo[hpool_len].resize = 0;
			
			hpool_len++;
			if(hpool_len == MAX_HACKS_N) goto sendchosenhacks; 
		}
	
	}

	if (runcopy->SjH__valid_rst_fake_seq) {
		
		/* valid RST with invalid SEQ */
		if ( percentage ( logarithm ( ct->packet_number ), 8 ) ) 
		{
			chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__valid_rst_fake_seq;
			chackpo[hpool_len].prcnt = 0;
			chackpo[hpool_len].debug_info = (char *)"valid RST with invalid SEQ";
			chackpo[hpool_len].resize = 0;
			
			hpool_len++;
			if(hpool_len == MAX_HACKS_N) goto sendchosenhacks; 
		}
	}

	if (runcopy->SjH__fake_syn) {
		
		/* fake SYN */
		if ( percentage ( logarithm ( ct->packet_number ), 11 ) ) 
		{
			chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__fake_syn;
			chackpo[hpool_len].prcnt = 94;
			chackpo[hpool_len].debug_info = (char *)"fake SYN";
			chackpo[hpool_len].resize = 0;
			
			hpool_len++;
			if(hpool_len == MAX_HACKS_N) goto sendchosenhacks; 
		}
	}

sendchosenhacks:

	/* -- FINALLY, SENT THE CHOOSEN PACKET(S) */
	if(hpool_len)
	{
		judge_t court_word;
		int i;

		for(i = 0; i < hpool_len; i++) 
		{
			if( chackpo[i].prcnt ) 
			{
				if( percentage( chackpo[i].prcnt, 100 ) ) 
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
			inj = packet_orphanotrophy( pb, chackpo[i].resize);

			/* copy ttl focus, required in last_pkt_fix */
			inj->tf = ct->tf;

			/* what the fuck do with the packets ? its the Court to choose */
			inj->wtf = court_word;

			/* calling finally the first kind of hack in the packet injected */
			(*this.*(chackpo[i].choosen_hack))( inj );
#ifdef HACKSDEBUG
			internal_log(NULL, HACKS_DEBUG,
				"** [%s] (lo:%d %s:%d #%d) id %u exp:%d wrk:%d len %d-%d[%d] data %d {%d%d%d%d%d}",
				chackpo[i].debug_info,
				ntohs(inj->tcp->source), 
				inet_ntoa( *((struct in_addr *)&inj->ip->daddr) ) ,
				ntohs(inj->tcp->dest), ct->packet_number,
				ntohs(inj->ip->id),
				ct->tf->expiring_ttl, ct->tf->min_working_ttl,
				inj->orig_pktlen,
				inj->pbuf_size, ntohs(inj->ip->tot_len),
				ntohs(inj->ip->tot_len) - ( (inj->ip->ihl * 4) + (inj->tcp->doff * 4) ),
				inj->tcp->syn, inj->tcp->ack, inj->tcp->psh, inj->tcp->fin, inj->tcp->rst
			);
#endif
		}
	}

	pb->status = SEND;
}

/* 
 * enque_ttl_probe has not the intelligence to understand if TTL bruteforcing 
 * is required or not more. Is called in different section of code
 */
void TCPTrack::enque_ttl_probe( struct packetblock *delayed_syn_pkt, struct sniffjoke_track *ct )
{
	unsigned char tested_ttl;
	/* 
	 * the first packet (the SYN) is used as starting point
	 * in the enque_ttl_burst to generate the series of 
	 * packets able to detect the number of hop distance 
	 * between our peer and the remote peer. the packet
	 * is lighty modify (ip->id change) and checksum fixed
	 */
	struct packetblock *injpb;

	/* enque_ttl_probe is called by two different section, the 
 	 * outgoing packet analysis and the KEEP packet analysis. here
 	 * is done a check about the working of our probe, for decretee
 	 * continuing or stopping to probe remote host
 	 */

	if(analyze_ttl_stats(ct))
		return;

	/* create a new packet buffer */
	injpb = get_free_pblock(delayed_syn_pkt->pbuf_size, HIGH, 0);

	/* LOCAL src, ready to be SEND, never collide with packet_id = 0 */
	injpb->packet_id = 0;
	injpb->proto = TCP;
	injpb->source = TTLBFORCE;
	injpb->status = SEND;

	/* the copy is done to keep refsyn ORIGINAL */
	memcpy( injpb->pbuf, delayed_syn_pkt->pbuf, delayed_syn_pkt->pbuf_size);

	update_pblock_pointers( injpb );

	/* 
 	 * if TTL expire and is generated and ICMP TIME EXCEEDED,
 	 * the iphdr is preserved and the tested_ttl found
 	 */
	ct->tf->sent_probe++;
	tested_ttl = ct->tf->sent_probe;
	injpb->ip->ttl = tested_ttl;
	injpb->tcp->source = ct->tf->puppet_port;
	injpb->tcp->seq = htonl(ct->tf->rand_key + tested_ttl);
	injpb->ip->id = (ct->tf->rand_key % 64) + tested_ttl;

	fix_iptcp_sum(injpb->ip, injpb->tcp);

#ifdef PACKETDEBUG
	internal_log(NULL, PACKETS_DEBUG,
		"Injecting probe %d, tested_ttl %d [exp %d min work %d], (dport %d sport %d) daddr %u",
		ct->tf->sent_probe,
		tested_ttl, 
		ct->tf->expiring_ttl, ct->tf->min_working_ttl, 
		ntohs(injpb->tcp->dest), ntohs(injpb->tcp->source),
		injpb->ip->daddr
	);
#endif
}

unsigned int TCPTrack::make_pkt_id( const unsigned char* pbuf )
{
	struct iphdr *ip = (struct iphdr *)pbuf;
	struct tcphdr *tcp;

	if(ip->protocol == IPPROTO_TCP)
	{
		tcp = (struct tcphdr *)((unsigned char *)ip + (ip->ihl * 4));
		return tcp->seq;
	}
	else
		return 0; /* packet_id == 0 mean no ID check */
}

bool TCPTrack::analyze_ttl_stats( struct sniffjoke_track *ct )
{
	if(ct->tf->sent_probe == maxttlprobe) 
	{
		ct->tf->status = TTL_UNKNOW;
		return true;
	}
	return false;
}

void TCPTrack::mark_real_syn_packets_SEND(unsigned int daddr) {

	struct packetblock *packet = NULL;

	packet = get_pblock(ANY_STATUS, ANY_SOURCE, TCP, false);
	while( packet != NULL )
	{
		if(packet->tcp->syn && packet->ip->daddr == daddr )
		{
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG, "The REAL SYN change status from KEEP to SEND");
#endif

			packet->status = SEND;
		}
		
		packet = get_pblock(ANY_STATUS, ANY_SOURCE, TCP, true);
	}
}

bool TCPTrack::check_uncommon_tcpopt( const struct tcphdr *tcp )
{
	unsigned char check;
	int i;

	for( i = sizeof(struct tcphdr); i < (tcp->doff * 4); i++)
	{
		check = ((unsigned char *)tcp)[i];

		switch( check ) 
		{
			case TCPOPT_TIMESTAMP:
				i += (TCPOLEN_TIMESTAMP +1 );
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
struct packetblock *
TCPTrack::packet_orphanotrophy( const struct packetblock* pb, int resize )
{
	struct packetblock *ret;
	int pbuf_size = 0;
	int iphlen = pb->ip->ihl * 4;
	int tcphlen = pb->tcp->doff * 4;
	int payload_len;
	int new_tot_len;

	/* 
	 * the packets generated could be resized, for the sniffjoke hack
 	 */
	switch(resize) 
	{
		case UNCHANGED_SIZE:
			pbuf_size = ntohs(pb->ip->tot_len) + (MAXOPTINJ * 3);
			new_tot_len = ntohs(pb->ip->tot_len);
 			payload_len = ntohs(pb->ip->tot_len) - ( iphlen + tcphlen );
			break;
		case 0:
			pbuf_size = iphlen + tcphlen + (MAXOPTINJ * 3);
			new_tot_len = iphlen + tcphlen;
 			payload_len = 0; 
			break;
		default:
			pbuf_size = iphlen + tcphlen + (MAXOPTINJ * 3) + resize;
			new_tot_len = iphlen + tcphlen + resize;
 			payload_len = resize; 
	}
	
	ret = get_free_pblock( pbuf_size, HIGH, 0);

	ret->packet_id = 0;
	ret->proto = TCP;
	ret->source = LOCAL;
	ret->status = SEND;
	ret->orig_pktlen = ntohs(pb->ip->tot_len);

	/* IP header copy , TCP header copy, Payload copy, if preserved */
	memcpy(ret->pbuf, pb->pbuf, iphlen + tcphlen + payload_len);

	update_pblock_pointers( ret );

	/* fixing the new length */
	ret->ip->tot_len = htons(new_tot_len);

	return ret;
}


/* 
 * this two functions is required on hacking injection, because that 
 * injection should happens ALWAYS, but give the less possible elements
 * to the attacker for detects sniffjoke working style
 */
bool TCPTrack::percentage( float math_choosed, int vecna_choosed )
{
	return ( (random() % 100) <= ( (int)(math_choosed * vecna_choosed ) / 100 ) );
}

/*	the variable is used from the sniffjoke routing for decreete the possibility of
 *	an hack happens. this variable are mixed in probabiliy with the ct->packet_number, because
 *	the hacks must happens, for the most, in the start of the session (the first 10 packets),
 *	other hacks injection should happen in the randomic mode express in logarithm function.
 */
float TCPTrack::logarithm( int packet_number )
{
	int blah;

	if(packet_number < 20)
		return 150.9;

	if(packet_number > 10000)
		blah = (packet_number / 10000) * 10000;
	else if(packet_number > 1000)
		blah = (packet_number / 1000) * 1000;
	else if(packet_number > 100)
		blah = (packet_number / 100) * 100;
	else
		return 2.2; /* x > 8 && x < 100 */

	if(blah == packet_number)
		return 90.0;
	else
		return 0.08;
}

unsigned int TCPTrack::half_cksum( const void *pointed_data, int len )
{
	unsigned int sum = 0x00;
	unsigned short carry = 0x00;
	unsigned short *data =(unsigned short *)pointed_data;

	while (len > 1)
	{
		sum += *data++;
		len -= 2;
	}

	if (len == 1)
	{
		*((unsigned short *) &carry) = *(unsigned char *) data;
		sum += carry;
	}

	return sum;
}

unsigned short TCPTrack::compute_sum(unsigned int sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short) ~sum;
}


void TCPTrack::fix_iptcp_sum( struct iphdr *iph, struct tcphdr *tcph )
{
	unsigned int sum;
	unsigned int l4len = ntohs(iph->tot_len) - (iph->ihl * 4);

	iph->check = 0;
	sum = half_cksum ((void *) iph, (iph->ihl * 4) );
	iph->check = compute_sum(sum);
	tcph->check = 0;
	sum = half_cksum ((void *) &iph->saddr, 8);
	sum += htons (IPPROTO_TCP + l4len );
	sum += half_cksum ((void *) tcph, l4len );
	tcph->check = compute_sum (sum);
}


/* 
 * the packet from the tunnel are put with lesser priority and the
 * hack-packet, injected from sniffjoke, are put in the better one.
 * when the software loop for in get_pblock(status, source, proto) the 
 * forged packet are send before the originals one.
 */
struct packetblock * TCPTrack::get_free_pblock( int pktsize, priority_t prio, unsigned int packet_id )
{
	int i, end, first_free = -1;

	if(prio == HIGH) {
		i = 0;
		end = (paxmax / 2);
	}
	else /* prio == LOW */ {
		i = (paxmax / 2);
		end = paxmax;
	}

	for(; i < end; i++) 
	{
		if(first_free == -1 && pblock_list[i].pbuf_size == 0) 
			first_free = i;
		
		/* 
 		 * packet_id == 0 is request when SJ need a packet slot for
 		 * put an hack packet inside the stream 
 		 *
 		 * otherwise, packet_id is returned by make_pkt_id and
 		 * is the sequence number. a RETRANSMISSION had the same
 		 * sequence number, for this reason I could drop duplicated
 		 * SYN
 		 */
		if(packet_id && pblock_list[i].packet_id == packet_id) 
		{
#ifdef PACKETDEBUG
			internal_log(NULL, PACKETS_DEBUG,
				"DUP: sequence number already present: (%08x) size: %d new size: %d",
				packet_id, 
				pblock_list[i].pbuf_size,
				pktsize
			);
#endif
			pblock_list[i].pbuf_size = pktsize;
			return &pblock_list[i];
		}
	}

	if ( first_free == -1 ) {
		struct packetblock *newlist;

		paxmax *= 2;

		newlist = (struct packetblock *)calloc( paxmax, sizeof( struct packetblock) );
		check_call_ret("memory allocation", errno, newlist == NULL ? -1 : 0, true );

		memcpy(	(void *)&newlist[0], 
			(void *)pblock_list, 
			sizeof(struct packetblock) * paxmax / 4 
		);
		
		memcpy( (void *)&newlist[paxmax / 2], 
			(void *)&pblock_list[paxmax / 4], 
			sizeof(struct packetblock) * paxmax / 4 
		);
		
		free(pblock_list);
		pblock_list = newlist;

		internal_log(NULL, DEBUG_LEVEL, 
			"### memory allocation for pblock_list in %s:%d:%s() new size: %d", __FILE__, __LINE__, __func__, 
			paxmax
		);

		first_free = paxmax / 4;
	}
	
	pblock_list[first_free].pbuf_size = pktsize;
		
	if ( first_free < paxmax / 2 )
		pblock_list_count[0]++;
	else
		pblock_list_count[1]++;
	
	return &pblock_list[first_free];
}

void TCPTrack::recompact_pblock_list(int what)
{
	if (paxmax > runcopy->max_packet_que )
	{
		struct packetblock *newlist;
		
		paxmax /= 2;

		newlist = (struct packetblock *)calloc( paxmax, sizeof( struct packetblock) );
		check_call_ret("memory allocation", errno, newlist == NULL ? -1 : 0, true );

		if(what == 0 ) {
			memcpy(	(void *)newlist, 
					(void *)&pblock_list[0], 
					sizeof(struct packetblock) * paxmax
			);
		} else /* what == 1 */ {
			memcpy(	(void *)newlist, 
					(void *)&pblock_list[paxmax], 
					sizeof(struct packetblock) * paxmax
			);
			pblock_list_count[0] = pblock_list_count[1];
		}
		
		pblock_list_count[1] = 0;
		
		free(pblock_list);
		pblock_list = newlist;
		
		internal_log(NULL, DEBUG_LEVEL,
			"### memory deallocation for pblock_list in %s:%d:%s() new size: %d", __FILE__, __LINE__, __func__, 
			paxmax
		);
	}
}

struct sniffjoke_track * TCPTrack::init_sexion( const struct packetblock *pb ) 
{
	int i, first_free = -1;
	for(i = 0; i < sextraxmax; i++) 
	{
		if( sex_list[i].daddr == 0 ) {
			first_free = i;
			break;
		}
	}

	if(first_free == -1) {
		/* realloc double size */
		sextraxmax *= 2;

		sex_list = (struct sniffjoke_track *)realloc( 
			(void *)sex_list,
			sizeof(struct sniffjoke_track) * sextraxmax
		);
		check_call_ret("memory allocation", errno, sex_list == NULL ? -1 : 0, true );

		memset(	(void *)&sex_list[sextraxmax / 2], 
			0x00, 
			(sizeof(struct sniffjoke_track) * sextraxmax / 2)
		);

		internal_log(NULL, DEBUG_LEVEL,
			"### memory allocation for sex_list in %s:%d:%s() new size: %d", __FILE__, __LINE__, __func__, 
			sextraxmax
		);

		first_free = sextraxmax / 2;
	}
	
	sex_list[first_free].daddr = pb->ip->daddr;
	sex_list[first_free].sport = pb->tcp->source;
	sex_list[first_free].dport = pb->tcp->dest;
	sex_list[first_free].isn = pb->tcp->seq;
	sex_list[first_free].packet_number = 1;
	sex_list[first_free].shutdown = false;

	/* pb is the refsyn, SYN packet reference for starting ttl bruteforce */
	sex_list[first_free].tf = find_ttl_focus(pb->ip->daddr, 1);

#ifdef PACKETDEBUG
	internal_log(NULL, PACKETS_DEBUG,
			"Session[%d]: local:%d -> %s:%d (ISN %08x) puppet %d TTL exp %d wrk %d", 
			first_free, ntohs(sex_list[first_free].sport), 
			inet_ntoa( *((struct in_addr *)&sex_list[first_free].daddr) ) ,
			ntohs(sex_list[first_free].dport),
			sex_list[first_free].isn,
			ntohs(sex_list[first_free].tf->puppet_port),
			sex_list[first_free].tf->expiring_ttl,
			sex_list[first_free].tf->min_working_ttl
	);
#endif

	if ( first_free < sextraxmax / 2 )
		sex_list_count[0]++;
	else
		sex_list_count[1]++;

	return &sex_list[first_free];
} 

/* get_sexion search for the session, if not found, return NULL */
struct sniffjoke_track * TCPTrack::get_sexion( unsigned int daddr, unsigned short sport, unsigned short dport )
{
	int i;

	for(i = 0; i < sextraxmax; i++) 
	{
		if(
			sex_list[i].daddr == daddr &&
			sex_list[i].sport == sport &&
			sex_list[i].dport == dport
		)
		{
			return &sex_list[i];
		}
	}

	return NULL;
}

/* find sexion must return a session, if a session is not found, a new one is 
 * created */
struct sniffjoke_track * TCPTrack::find_sexion( const struct packetblock *pb ) 
{
	struct sniffjoke_track *ret;

	if((ret = get_sexion( pb->ip->daddr, pb->tcp->source, pb->tcp->dest )) != NULL)
		return ret;
	else 		
		return init_sexion( pb );
}

/* clear_sexion: clear a session in two step, the first RST/FIN set shutdown 
 * variable to true, the second close finally.
 */
void TCPTrack::clear_sexion( struct sniffjoke_track *used_ct ) 
{
	int i;

	for(i = 0 ; i < sextraxmax; i++)
	{
		if( &(sex_list[i]) == used_ct )
		{
			if(used_ct->shutdown == false) 
			{
				internal_log(NULL, DEBUG_LEVEL,
					"SHUTDOWN sexion [%d] sport %d dport %d daddr %u",
					i, ntohs(used_ct->sport), ntohs(used_ct->dport), used_ct->daddr
				);
				used_ct->shutdown = true;
			}
			else {
				internal_log(NULL, DEBUG_LEVEL,
					"Removing session[%d]: local:%d -> %s:%d TTL exp %d wrk %d #%d", 
					i, ntohs(sex_list[i].sport), 
					inet_ntoa( *((struct in_addr *)&used_ct->daddr) ) ,
					ntohs(used_ct->dport),
					used_ct->tf->expiring_ttl,
					used_ct->tf->min_working_ttl,
					used_ct->packet_number
				);
				
				memset( (void *)used_ct, 0x00, sizeof(struct sniffjoke_track ) );
				
				if ( i < sextraxmax / 2 ) {
					sex_list_count[0]--;
					if (sex_list_count[0] == 0)
						recompact_sex_list(0);
				} else {
					sex_list_count[1]--;
					if (sex_list_count[1] == 0)
						recompact_sex_list(1);
				}
			}

			return;
		}
	}
	
	check_call_ret("unforeseen bug: TCPTrack.cc, contact the package mantainer, sorry. function clear_sexion", 0, -1, true);
}

void TCPTrack::recompact_sex_list( int what )
{
	if (sextraxmax > runcopy->max_session_tracked )
	{
		struct sniffjoke_track *newlist;
		
		sextraxmax /= 2;

		newlist = (struct sniffjoke_track *)calloc( sextraxmax, sizeof( struct sniffjoke_track ) );
		check_call_ret("memory allocation", errno, newlist == NULL ? -1 : 0, true );

		switch( what )
		{
			case 0: /* first half */
				memcpy(	(void *)newlist, 
						(void *)&sex_list[0], 
						sizeof(struct sniffjoke_track) * sextraxmax
				);
				break;
			case 1: /* second half */
				memcpy(	(void *)newlist, 
						(void *)&sex_list[sextraxmax], 
						sizeof(struct sniffjoke_track) * sextraxmax
				);
				sex_list_count[0] = sex_list_count[1];
				break;
		}
		
		sex_list_count[1] = 0;

		free(sex_list);
		sex_list = newlist;
		
		internal_log(NULL, DEBUG_LEVEL,
			"### memory deallocation for sex_list in %s:%d:%s() new size: %d", __FILE__, __LINE__, __func__, 
			sextraxmax
		);
	}
}

struct ttlfocus *TCPTrack::init_ttl_focus( int first_free, unsigned int destip )
{
		if (first_free == -1) {
			maxttlfocus *= 2;
			ttlfocus_list = (struct ttlfocus *)realloc( 
				(void *)ttlfocus_list, 
				sizeof(struct ttlfocus) * maxttlfocus 
			);
			
			check_call_ret("memory allocation", errno, ttlfocus_list == NULL ? -1 : 0, true );
			
			memset(	(void *)&ttlfocus_list[maxttlfocus / 2], 
				0x00, 
				(sizeof(struct ttlfocus) * maxttlfocus / 2)
			);
			
			internal_log(NULL, DEBUG_LEVEL,
				"### memory allocation for ttlfocus_list in %s:%d:%s() new size: %d", __FILE__, __LINE__, __func__, 
				maxttlfocus
			);
			
			first_free = maxttlfocus / 2;
		}

		ttlfocus_list[first_free].daddr = destip;
		ttlfocus_list[first_free].min_working_ttl = 0xff;
		ttlfocus_list[first_free].status = TTL_BRUTALFORCE;
		ttlfocus_list[first_free].rand_key = random();
		ttlfocus_list[first_free].puppet_port = htons( (random() % 15000) + 1100 );
		
		return &ttlfocus_list[first_free];
} 

/* 
 * find_ttl_focus is used whenever you need a ttlfocus struct, this struct is used
 * as reference for each conntrack with the same distination address. every session
 * had access in the same ttlfocus.
 * 
 * in ttlfocus are keep the informations for ttl bruteforcing
 */
struct ttlfocus *TCPTrack::find_ttl_focus( unsigned int destip, int initialize )
{
	int i, first_free = -1;

	for(i = 0; i < maxttlfocus; i++) 
	{
		if( first_free == -1 && ttlfocus_list[i].daddr == 0)
			first_free = i;
			
		if( ttlfocus_list[i].daddr == destip )
			return &ttlfocus_list[i];
	}

	if(initialize == 0)
		return NULL;

	return init_ttl_focus( first_free, destip );
}

/*
 * TCP/IP hacks, focus:
 *
 *	suppose the sniffer reconstruction flow, suppose which variable they use, make them
 *	variables fake and send a packet that don't ruin the real flow.
 *
 * SjH__ = sniffjoke hack
 *
 */
void TCPTrack::SjH__fake_data( struct packetblock *hackp )
{
	int i, diff;

	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));

	diff = ntohs(hackp->ip->tot_len) - ( (hackp->ip->ihl * 4) + (hackp->tcp->doff * 4) );

	for(i = 0; i < (diff - 3); i += 4)
		*(unsigned int *)(&hackp->payload[i]) = random();
}

void TCPTrack::SjH__fake_seq( struct packetblock *hackp )
{
	int what = (random() % 3);

	/* 
	 * MAXOPTINJ is used * 3 because the packet can be incremented in size here,
	 * have ipopt and tcpopt. This variable should, and is better if became random
	 * instead of fixed value.
	 */
	if( !hackp->payload ) {
		hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) + MAXOPTINJ);
		hackp->ip->tot_len = htons(ntohs(hackp->ip->tot_len) + MAXOPTINJ);
	}
	else
		if(what == 0)
			what = 2;

	if(what == 2) 
		hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) + (random() % 5000));

	else /* what == 1 */
		hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) - (random() % 5000));

	hackp->tcp->window = htons((random() % 80) * 64);
	hackp->tcp->ack = 0;
	hackp->tcp->ack_seq = 0;

	SjH__fake_data(hackp);
}

/* fake syn, same more or less value, but, fake */
void TCPTrack::SjH__fake_syn( struct packetblock *hackp )
{
	hackp->tcp->psh = 0;
	hackp->tcp->syn = 1;

	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));
	hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) + 65535 + (random() % 5000));

	/* 20% is a SYN ACK */
	if( (random() % 5) == 0 ) 
	{
		hackp->tcp->ack = 1;
		hackp->tcp->ack_seq = random();
	}
	else 
	{
		hackp->tcp->ack = 0;
		hackp->tcp->ack_seq = 0;
	}

	/* payload is always truncated */
	hackp->ip->tot_len = htons( (hackp->ip->ihl * 4) + (hackp->tcp->doff * 4) );

	/* 20% had source and dest port reversed */
	if( (random() % 5) == 0) 
	{
		unsigned short swap = hackp->tcp->source;
		hackp->tcp->source = hackp->tcp->dest;
		hackp->tcp->dest = swap;
	}
}

void TCPTrack::SjH__fake_close( struct packetblock *hackp )
{
	int original_size = hackp->orig_pktlen - (hackp->ip->ihl * 4) - (hackp->tcp->doff * 4);
	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));

	/* fake close could have FIN+ACK or RST+ACK */
	hackp->tcp->psh = 0;

	if(random() % 2) 
		hackp->tcp->fin = 1;
	else 
		hackp->tcp->rst = 1;

	/* in both case, the sequence number must be shrink as no data are there.
 	 * the ack_seq is set because the ACK flag is checked to be 1 */
	hackp->tcp->seq = htonl( ntohl(hackp->tcp->seq) - original_size + 1 );
}

void TCPTrack::SjH__zero_window( struct packetblock *hackp )
{
	hackp->tcp->syn = hackp->tcp->fin = hackp->tcp->rst = 1;
	hackp->tcp->psh = hackp->tcp->ack = 0;
	hackp->tcp->window = 0;
}

void TCPTrack::SjH__shift_ack( struct packetblock *hackp )
{
	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));
	hackp->tcp->ack_seq = htonl(ntohl(hackp->tcp->ack_seq) + 65535 );
}

void TCPTrack::SjH__valid_rst_fake_seq( struct packetblock *hackp )
{
	/* 
 	 * if the session is resetted, the remote box maybe vulnerable to:
 	 * Slipping in the window: TCP Reset attacks
 	 * http://kerneltrap.org/node/3072
 	 */
 	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));
	hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) + 65535 + (random() % 12345));
	hackp->tcp->window = (unsigned short)(-1);
	hackp->tcp->rst = hackp->tcp->ack = 1;
	hackp->tcp->ack_seq = htonl(ntohl(hackp->tcp->seq + 1));
	hackp->tcp->fin = hackp->tcp->psh = hackp->tcp->syn = 0;
}

/* ipopt IPOPT_RR inj*/
void TCPTrack::SjH__inject_ipopt( struct packetblock *hackp )
{
	int iphlen = hackp->ip->ihl * 4;
	int tcphlen = hackp->tcp->doff * 4;
	int l47len;
	int route_n = (random() % 5) + 5; /* 5 - 9 */
	int fakeipopt = ( (route_n + 1) * 4);
	unsigned char *endip = hackp->pbuf + sizeof(struct iphdr);
	int startipopt = iphlen - sizeof(struct iphdr);
	int i;

	/* l47len = length of the frame layer 4 to 7 */
	l47len = ntohs(hackp->ip->tot_len) - iphlen;

	/* 1: strip the original ip options, if present */	
	if( iphlen > sizeof(struct iphdr) ) 
	{
		memmove(endip, endip + startipopt, l47len);

		l47len = ntohs(hackp->ip->tot_len) - sizeof(struct iphdr);
		iphlen = sizeof(struct iphdr);
	}

	/* 2: shift the tcphdr and the payload bytes after the reserved space to IPOPT_RR */
	memmove(endip + fakeipopt, endip, l47len);
	hackp->tcp = (struct tcphdr *)(endip + fakeipopt);
	hackp->payload = (unsigned char *)hackp->tcp + tcphlen;

	endip[0] = IPOPT_NOP;
	endip[1] = IPOPT_RR;		/* IPOPT_OPTVAL */
	endip[2] = (route_n * 4) + 3;	/* IPOPT_OLEN   */
	endip[3] = 4;			/* IPOPT_OFFSET = IPOPT_MINOFF */

	for(i = 4; i != fakeipopt; i += 4 )
		*(unsigned int *)(&endip[i]) = random();

#ifdef HACKSDEBUG
	internal_log(NULL, HACKS_DEBUG,
		"Inj IpOpt (lo:%d %s:%d) (route_n %d) id %u l47 %d tot_len %d -> %d {%d%d%d%d%d}",
		ntohs(hackp->tcp->source), 
		inet_ntoa( *((struct in_addr *)&hackp->ip->daddr) ) ,
		ntohs(hackp->tcp->dest), 
		route_n,
		ntohs(hackp->ip->id),
		l47len,
		ntohs(hackp->ip->tot_len),
		(iphlen + fakeipopt + l47len),
		hackp->tcp->syn, hackp->tcp->ack, hackp->tcp->psh, hackp->tcp->fin, hackp->tcp->rst
	);
#endif
	hackp->ip->ihl = 5 + route_n + 1;  /* 20 byte ip hdr, route_n * 4 byte options + 4 byte */
	hackp->ip->tot_len = htons((hackp->ip->ihl * 4) + l47len);
}

/* tcpopt TCPOPT_TIMESTAMP inj with bad TCPOLEN_TIMESTAMP */
void TCPTrack::SjH__inject_tcpopt( struct packetblock *hackp ) 
{
	int iphlen = hackp->ip->ihl * 4;
	int tcphlen = hackp->tcp->doff * 4;
	int l57len;
	int faketcpopt = 8;
	unsigned char *endtcp = hackp->pbuf + iphlen + sizeof(struct tcphdr);
	int starttcpopt = tcphlen - sizeof(struct tcphdr);
	time_t now = time(NULL);

	/* l57len = length of the frame layer 5 to 7 */
	l57len = ntohs(hackp->ip->tot_len) - ( iphlen + tcphlen );

	if(tcphlen > sizeof(struct tcphdr))
	{
		/* 1: strip the original ip options, if present */
		memmove(endtcp, endtcp + starttcpopt, tcphlen);
		
		l57len = ntohs(hackp->ip->tot_len) - ( iphlen + sizeof(struct tcphdr) );
		tcphlen = sizeof(struct tcphdr);
	}
	
	/* 2: shift the payload after the reserved space to faketcpopt */
	memmove(endtcp + faketcpopt, endtcp, l57len);

	endtcp[0] = TCPOPT_NOP;
	endtcp[1] = TCPOPT_NOP;
	endtcp[2] = TCPOPT_TIMESTAMP;
	endtcp[3] = 6;

	/*	6 is an invalid value;
	 *	from: /usr/include/netinet/tcp.h:
	 *	# define TCPOLEN_TIMESTAMP      10
	 */

	/* time_t, 4 byte of time stamp value */
	memcpy(&endtcp[4], &now, sizeof(time_t));

#ifdef HACKSDEBUG
	internal_log(NULL, HACKS_DEBUG,
		"Fake TcpOpt (lo:%d %s:%d) id %u l57 %d tot_len %d -> %d {%d%d%d%d%d}",
		ntohs(hackp->tcp->source), 
		inet_ntoa( *((struct in_addr *)&hackp->ip->daddr) ) ,
		ntohs(hackp->tcp->dest), 
		ntohs(hackp->ip->id),
		l57len,
		ntohs(hackp->ip->tot_len),
		(iphlen + tcphlen + faketcpopt + l57len),
		hackp->tcp->syn, hackp->tcp->ack, hackp->tcp->psh, hackp->tcp->fin, hackp->tcp->rst
	);
#endif
	hackp->tcp->doff = (sizeof(struct tcphdr) + 2) & 0xf;
	hackp->ip->tot_len = htons(iphlen + tcphlen + faketcpopt + l57len);
}
