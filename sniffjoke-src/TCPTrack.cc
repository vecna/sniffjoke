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

#include "sniffjoke.hh"

// define DEBUG enable session debug, ttl bruteforce 
// #define DEBUG 
// define HACKSDEBUG enable dump about packet injected
// #define HACKSDEBUG

TCPTrack::TCPTrack(SjConf *sjconf) 
{
	int i;

	runcopy = sjconf->running;

	sextraxmax = runcopy->max_session_tracked;
	paxmax = runcopy->max_packet_que;
	maxttlfocus = runcopy->max_tracked_ttl;
	maxttlprobe = runcopy->max_ttl_probe;

	sex_list = (struct sniffjoke_track *)calloc( sextraxmax, sizeof(struct sniffjoke_track) );
	check_call_ret("memory allocation", errno, sex_list == NULL ? -1 : 0 );

	pblock_list = (struct packetblock *)calloc( paxmax, sizeof(struct packetblock) );
	check_call_ret("memory allocation", errno, pblock_list == NULL ? -1 : 0 );
   
	ttlfocus_list = (struct ttlfocus *)calloc( maxttlfocus, sizeof(struct ttlfocus) );
	check_call_ret("memory allocation", errno, ttlfocus_list == NULL ? -1 : 0 );

	sex_list_count[0] = 0;
	sex_list_count[1] = 0;
	pblock_list_count[0] = 0;
	pblock_list_count[1] = 0;

	for( i = 0; i < (random() % 40) ; i++ ) 
		srandom( (unsigned int)time(NULL) ^ random() );
}

TCPTrack::~TCPTrack() {
	printf("TCPTrack: freeing %d session list, %d packet queue, %d tracked ttl\n",
		sextraxmax, paxmax, maxttlfocus
	);
	free(sex_list);
	free(pblock_list);
	free(ttlfocus_list);
}

/* the packet is add in the packet queue for be analyzed in a second time */
void TCPTrack::add_packet_queue(source_t source, unsigned char *buff, int nbyte) 
{
	struct packetblock *target;
	unsigned int packet_id = make_pkt_id( (struct iphdr *)buff );

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
	target = get_free_pblock( nbyte + (MAXOPTINJ * 3), LOW, packet_id );

	target->packet_id = packet_id;
	target->source = source;
	target->status = YOUNG;
	target->wtf = INNOCENT;
	target->orig_pktlen = nbyte;

	memcpy(target->pbuf, buff, nbyte);
	
	update_pblock_pointers( target );
}

void TCPTrack::update_pblock_pointers( struct packetblock *pb ) {

	pb->ip = (struct iphdr *)pb->pbuf;

	if(pb->ip->protocol == IPPROTO_TCP) {
		pb->proto = TCP;
		pb->tcp = (struct tcphdr *)(((unsigned char *)pb->ip) + (pb->ip->ihl * 4));
	} else if (pb->ip->protocol == IPPROTO_ICMP) {
		pb->proto = ICMP;
		pb->icmp = (struct icmphdr *)(((unsigned char *)pb->ip) + (pb->ip->ihl * 4));
	} else {
		pb->proto = OTHER_IP;
	}
}

/* 
 * this is the "second time", the received packet are assigned in a tracked TCP session,
 * for understand which kind of mangling should be apply. maybe not all packets is sent 
 * immediatly, this happens when sniffjoke require some time (and some packets) for
 * detect the hop distance between the remote peer.
 *
 * as defined in sniffjoke.hh, the "status" variable could have these status:
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
	unsigned int last_packet_id = 0;

	newp = get_pblock(YOUNG, NETWORK, ICMP, 0, 0);
	while ( newp != NULL )
	{
		/* 
 		 * a TIME_EXCEEDED packet should contains informations
 		 * for discern HOP distance from a remote host
 		 */
		if(newp->icmp->type == ICMP_TIME_EXCEEDED) 
			analyze_incoming_icmp(newp);

		/* if packet exist again = is not destroyed by analyze function */
		if(newp->status == YOUNG)
			newp->status = SEND;
		
		newp = get_pblock(YOUNG, NETWORK, ICMP, 0, 1);
	}

	/* 
 	 * incoming TCP. sniffjoke algorithm open/close sessions and detect TTL
 	 * lists analyzing SYN+ACK and FIN|RST packet
 	 */
 	newp = get_pblock(YOUNG, NETWORK, TCP, 0, 0);
	while ( newp != NULL ) 
	{
		if(newp->tcp->syn && newp->tcp->ack)
			analyze_incoming_synack(newp);

		if(newp->status == YOUNG && (newp->tcp->rst || newp->tcp->fin))
			analyze_incoming_rstfin(newp);	

		/* if packet exist again = is not destroyed by analyze function */
		if(newp->status == YOUNG)
			newp->status = SEND;
			
		newp = get_pblock(YOUNG, NETWORK, TCP, 0, 1);
	}

	/* outgoing TCP packets ! */
	newp = get_pblock(YOUNG, TUNNEL, TCP, 0, 0);
	while ( newp != NULL )
	{
#if 0
		if(! (ntohs(newp->tcp->dest) == 80) || (ntohs(newp->tcp->source) == 80)) {
			newp->status = SEND; 
			continue;
		}
#else
		/* check configuration TODO, at the moment, all session are sniffjokeble */
#endif

		/* 
 		 * create/close session, check ttlfocus and start new discovery, 
 		 * this function contains the core functions of sniffjoke: 
 		 * enque_ttl_probe and inject_hack_in_queue 
 		 *
 		 * those packets had ttlfocus set inside
 		 */
		manage_outgoing_packets(newp);

		if(newp->status == YOUNG)
			newp->status = SEND;
			
		newp = get_pblock(YOUNG, TUNNEL, TCP, 0, 1);
	}

	/* last_packet_id is used to avoid repeats in get_pblock return value */
	int i = 0;
	newp = get_pblock(KEEP, TUNNEL, TCP, last_packet_id, 0);
	while ( newp != NULL ) 
	{
		last_packet_id = make_pkt_id(newp->ip);
		ct = find_sexion( newp );

		if(ct->tf->status == TTL_BRUTALFORCE) 
		{
#ifdef DEBUG
			printf("status BRUTALFORCE for %s: %d %d pkt is KEEP (%d), send probe %d rcvd %d probe\n",
				inet_ntoa( *((struct in_addr *)&ct->tf->daddr) ) ,
				ntohs(newp->tcp->source), 
				ntohs(newp->tcp->dest),
				ct->tf->status, ct->tf->sent_probe, ct->tf->received_probe
			);
#endif
			enque_ttl_probe( newp, ct );
		}
		newp = get_pblock(KEEP, TUNNEL, TCP, last_packet_id, 1);
	}

	/* all others YOUNG packets must be send immediatly */
	newp = get_pblock(YOUNG, ANY_SOURCE, ANY_PROTO, 0, 0);
	while ( newp != NULL ) 
	{
		newp->status = SEND;
		newp = get_pblock(YOUNG, ANY_SOURCE, ANY_PROTO, 0, 1);
	}
}

void TCPTrack::analyze_incoming_icmp(struct packetblock *timeexc)
{
	struct iphdr *badiph;
	struct tcphdr *badtcph;
	struct ttlfocus *tf;

	badiph = (struct iphdr *)(((unsigned char *)timeexc->ip + 
			(timeexc->ip->ihl * 4) + sizeof(struct icmphdr)));
	badtcph =(struct tcphdr *)((unsigned char *)badiph + (badiph->ihl *4));

	tf = find_ttl_focus(badiph->daddr, 0);

	if(tf != NULL && badiph->protocol == IPPROTO_TCP) 
	{
		unsigned char expired_ttl = badiph->id - (tf->rand_key % 64);
		unsigned char exp_double_check = ntohl(badtcph->seq) - tf->rand_key;

		if(tf->status != TTL_KNOW && expired_ttl == exp_double_check ) 
		{
			tf->received_probe++;

			if( expired_ttl > tf->expiring_ttl) {
#ifdef DEBUG
				printf("TTL OK: (sent %d recvd %d) previous %d now %d\n", 
					tf->sent_probe, tf->received_probe,
					tf->expiring_ttl, expired_ttl
				);
#endif
				tf->expiring_ttl = expired_ttl;
			}
#ifdef DEBUG
			else {
				printf("TTL BAD: (sent %d recvd %d) previous %d now %d\n", 
					tf->sent_probe, tf->received_probe,
					tf->expiring_ttl, expired_ttl
				);
			}
#endif
		}
		clear_pblock(timeexc);
	}
	else {
		timeexc->status = SEND;
	}
}

void TCPTrack::analyze_incoming_synack(struct packetblock *synack)
{
	struct ttlfocus *tf;

	/* NETWORK is src: dest port and source port inverted and saddr are used, 
 	 * source is put as last argument (puppet port)
	 */
	if((tf = find_ttl_focus( synack->ip->saddr, 0)) == NULL) 
		return;

#ifdef DEBUG 
	printf("SYN/ACK (saddr %u) seq %08x seq_ack %08x - dport %d sport %d puppet %d\n",
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

#ifdef DEBUG
		printf("discern_ttl %d: min working ttl %d expiring ttl %d recv probe %d sent probe %d\n", 
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

void TCPTrack::analyze_incoming_rstfin(struct packetblock *rstfin) 
{
	struct sniffjoke_track *ct;

#ifdef DEBUG
	printf("RST/FIN received (NET): ack_seq %08x, sport %d dport %d saddr %u\n",
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

void TCPTrack::manage_outgoing_packets(struct packetblock *newp)
{
	struct sniffjoke_track *ct;

	/* 
 	 * get_sexion return an existing sexion or even NULL, 
 	 * find_sexion create a new, if required 
 	 */
	if(newp->tcp->syn) 
	{
		ct = find_sexion( newp );
#ifdef DEBUG
		printf("SYN from TUNNEL:%d %s:%d\n",
			ntohs(newp->tcp->source),
			inet_ntoa( *((struct in_addr *)&newp->ip->daddr) ),
			ntohs(newp->tcp->dest) 
		);
#endif
		/* if sniffjoke had not yet the minimum working ttl, continue the starting probe */
		if(ct->tf->status == TTL_BRUTALFORCE) 
		{
#ifdef DEBUG
			printf("SYN retransmission - DROPPED\n");
#endif	
			enque_ttl_probe( newp, ct );
			newp->status = KEEP; 
			return;
		}
	}

	/* all outgoing packets, exception for starting SYN, is send immediatly */
	newp->status = SEND;
	
	ct = get_sexion( newp->ip->daddr, newp->tcp->source, newp->tcp->dest);

	if( ct != NULL && ( newp->tcp->rst || newp->tcp->fin ) )
	{
#ifdef DEBUG
		printf("FIN/RST (TUN) clear: seq %08x seq_ack %08x (rst %d fin %d ack %d) dport %d sport %d)\n",
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
	}

	if( ct == NULL)
		return;

	ct->packet_number++;
	newp->tf = ct->tf;

	/* update_session_stat( xml_stat_root, ct ); */

	/* a closed or shutdown session don't require to be hacked */
	if(newp->tcp->fin || newp->tcp->rst)
		return;

	inject_hack_in_queue( newp, ct );
}

/* 
 * the packet from the tunnel are put with lesser priority and the
 * hack-packet, injected from sniffjoke, are put in the better one.
 * when the software loop for in get_pblock(status, source, proto) the 
 * forged packet are send before the originals one.
 */
struct packetblock * TCPTrack::get_free_pblock(int pktsize, priority_t prio, unsigned int packet_id)
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
 		 * is the sequence number. a RETRANSMISSION had the some
 		 * sequence number, for this reason I could drop duplicated
 		 * SYN
 		 */
		if(packet_id && pblock_list[i].packet_id == packet_id) 
		{
#ifdef DEBUG
			printf("DUP: sequence number already present: (%08x) size: %d new size: %d\n", 
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
		check_call_ret("memory allocation", errno, newlist == NULL ? -1 : 0 );

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

		printf("### memory allocation for pblock_list in %s:%d:%s() new size: %d\n", __FILE__, __LINE__, __func__, paxmax);

		first_free = paxmax / 4;
	}
	
	pblock_list[first_free].pbuf_size = pktsize;
		
	if ( first_free < paxmax / 2 )
		pblock_list_count[0]++;
	else
		pblock_list_count[1]++;
	
	return &pblock_list[first_free];
}

struct packetblock * TCPTrack::get_pblock(status_t status, source_t source, proto_t proto, unsigned int pkt_id, int must_continue) 
{
	static int start_index = 0;
	int i;
	bool ignore_until = true;

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

		if(pkt_id && (pkt_id == pblock_list[i].packet_id)) {
			ignore_until = false;
			continue;
		}

		if(pkt_id && ignore_until)
			continue;
		
		update_pblock_pointers( &pblock_list[i] );
		
		start_index = i + 1;
		return &(pblock_list[i]);
	}

	return NULL;
}

void TCPTrack::clear_pblock(struct packetblock *used_pb)
{
	int i;
	int free = 1;

	for(i = 0; i < paxmax; i++) 
	{		
		if( &(pblock_list[i]) == used_pb ) 
		{
			memset(used_pb, 0x00, sizeof(struct packetblock));
			
			if ( i < paxmax /2 )
				pblock_list_count[0]--;
			else
				pblock_list_count[1]--;
			
			if (pblock_list_count[0] == 0)
				recompact_pblock_list(0);
			else if (pblock_list_count[1] == 0)
				recompact_pblock_list(1);
				
			return;
		}
	}
		
	check_call_ret("unforeseen bug: TCPTrack.cc, function clear_pblock", 0, -1);
}

void TCPTrack::recompact_pblock_list(int what)
{
	if (paxmax > runcopy->max_packet_que )
	{
		struct packetblock *newlist;
		
		paxmax /= 2;

		newlist = (struct packetblock *)calloc( paxmax, sizeof( struct packetblock) );
		check_call_ret("memory allocation", errno, newlist == NULL ? -1 : 0 );

		switch( what )
		{
			case 0:
				memcpy(	(void *)newlist, 
						(void *)&pblock_list[0], 
						sizeof(struct packetblock) * paxmax
				);
				break;
			case 1:
				memcpy(	(void *)newlist, 
						(void *)&pblock_list[paxmax], 
						sizeof(struct packetblock) * paxmax
				);
				pblock_list_count[0] = pblock_list_count[1];
				break;
		}
		
		pblock_list_count[1] = 0;
		
		free(pblock_list);
		pblock_list = newlist;
		
		printf("### memory deallocation for pblock_list in %s:%d:%s() new size: %d\n", __FILE__, __LINE__, __func__, paxmax);
		
	}
}

/* get_sexion search for the session, if not found, return NULL */
struct sniffjoke_track * TCPTrack::get_sexion( unsigned int daddr, unsigned short sport, unsigned short dport)
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

struct sniffjoke_track * TCPTrack::init_sexion( struct packetblock *pb ) 
{
	int i, first_free = -1;
	for(i = 0; i < sextraxmax; i++) 
	{
		if( sex_list[i].daddr == 0 )
			first_free = i;
	}

	if(first_free == -1) {
		/* realloc double size */
		sextraxmax *= 2;

		sex_list = (struct sniffjoke_track *)realloc( 
			(void *)sex_list,
			sizeof(struct sniffjoke_track) * sextraxmax
		);
		check_call_ret("memory allocation", errno, sex_list == NULL ? -1 : 0 );

		memset(	(void *)&sex_list[sextraxmax / 2], 
			0x00, 
			(sizeof(struct sniffjoke_track) * sextraxmax / 2)
		);

		printf("### memory allocation for sex_list in %s:%d:%s() new size: %d\n", __FILE__, __LINE__, __func__, sextraxmax);

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
	
	printf("Session[%d]: local:%d -> %s:%d (ISN %08x) puppet %d TTL exp %d wrk %d \n", 
			first_free, ntohs(sex_list[first_free].sport), 
			inet_ntoa( *((struct in_addr *)&sex_list[first_free].daddr) ) ,
			ntohs(sex_list[first_free].dport),
			sex_list[first_free].isn,
			ntohs(sex_list[first_free].tf->puppet_port),
			sex_list[first_free].tf->expiring_ttl,
			sex_list[first_free].tf->min_working_ttl
	);

	if ( first_free < sextraxmax / 2 )
		sex_list_count[0]++;
	else
		sex_list_count[1]++;

	return &sex_list[first_free];
} 

/* find sexion must return a session, if a session is not found, a new one is 
 * created */
struct sniffjoke_track * TCPTrack::find_sexion( struct packetblock *pb ) 
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
			if(used_ct->shutdown == false) {
#ifdef DEBUG
				printf("SHUTDOWN sexion [%d] sport %d dport %d daddr %u\n",
					i, ntohs(used_ct->sport), ntohs(used_ct->dport), used_ct->daddr
				);
#endif
				used_ct->shutdown = true;
			}
			else {
				printf("Removing session[%d]: local:%d -> %s:%d TTL exp %d wrk %d #%d\n", 
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
}

void TCPTrack::recompact_sex_list(int what)
{
	if (sextraxmax > runcopy->max_session_tracked )
	{
		struct sniffjoke_track *newlist;
		
		sextraxmax /= 2;

		newlist = (struct sniffjoke_track *)calloc( sextraxmax, sizeof( struct sniffjoke_track ) );
		check_call_ret("memory allocation", errno, newlist == NULL ? -1 : 0 );

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
		
		printf("### memory deallocation for sex_list in %s:%d:%s() new size: %d\n", __FILE__, __LINE__, __func__, sextraxmax);

		free(sex_list);
		sex_list = newlist;
	}
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
 * the packet mangling is the some, the sendint type is choosen randomly by packets_court(),
 * and the programmer should change the probability of the choose.
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

#if 0
	if ( pb->tcp->ack ) 
	{
		/* SHIFT ack */
		if ( percentage ( logarithm ( ct->packet_number ), 15 ) ) 
		{
			chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__shift_ack;
			chackpo[hpool_len].prcnt = 0;
			chackpo[hpool_len].debug_info = "shift ACK";
			chackpo[hpool_len].resize = UNCHANGED_SIZE;
			hpool_len++;
		}
	}
#endif 
	int payload_len = ntohs(pb->ip->tot_len) - ((pb->ip->ihl * 4) + (pb->tcp->doff * 4));

	if ( payload_len ) 
	{
		/* fake DATA injection in stream */
		if ( percentage ( logarithm ( ct->packet_number ), 10 ) ) 
		{
			chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__fake_data;
			chackpo[hpool_len].prcnt = 98;
			chackpo[hpool_len].debug_info = (char *)"fake data";
			chackpo[hpool_len].resize = UNCHANGED_SIZE; 
			hpool_len++;
		}

	}

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
	}

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
		}
	}

	/* zero window, test */
	if ( percentage ( logarithm ( ct->packet_number ), 3 ) ) 
	{
		chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__zero_window;
		chackpo[hpool_len].prcnt = 95;
		chackpo[hpool_len].debug_info = (char *)"zero window";
		chackpo[hpool_len].resize = 0;
		hpool_len++;
	}

	/* valid RST with invalid SEQ */
	if ( percentage ( logarithm ( ct->packet_number ), 8 ) ) 
	{
		chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__valid_rst_fake_seq;
		chackpo[hpool_len].prcnt = 0;
		chackpo[hpool_len].debug_info = (char *)"valid RST bad SEQ";
		chackpo[hpool_len].resize = 0;
		hpool_len++;
	}

	/* fake SYN */
	if ( percentage ( logarithm ( ct->packet_number ), 11 ) ) 
	{
		chackpo[hpool_len].choosen_hack = &TCPTrack::SjH__fake_syn;
		chackpo[hpool_len].prcnt = 94;
		chackpo[hpool_len].debug_info = (char *)"fake SYN";
		chackpo[hpool_len].resize = 0;
		hpool_len++;
	}

	/* -- FINALLY, SENT THE CHOOSEN PACKET(S) */
	if(hpool_len) /* hpool_len < than MAX_HACKS_N */
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
			inj = packet_orphanotrophy( pb->ip, pb->tcp, chackpo[i].resize);

			/* copy ttl focus, required in last_pkt_fix */
			inj->tf = ct->tf;

			/* what the fuck do with the packets ? its the Court to choose */
			inj->wtf = court_word;

			/* calling finally the first kind of hack in the packet injected */
			(*this.*(chackpo[i].choosen_hack))( inj );
#ifdef HACKSDEBUG
			printf("** [%s] (lo:%d %s:%d #%d) id %u exp:%d wrk:%d len %d-%d[%d] data %d {%d%d%d%d%d}\n",
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

bool TCPTrack::analyze_ttl_stats(struct sniffjoke_track *ct)
{
	if(ct->tf->sent_probe == maxttlprobe) 
	{
		ct->tf->status = TTL_UNKNOW;
		return true;
	}
	return false;
}

void TCPTrack::mark_real_syn_packets_SEND(unsigned int daddr) {
	struct packetblock *refsyn = NULL;

	int i;

	for(i = 0; i < paxmax; i++) 
	{
		pblock_list[i].ip = (struct iphdr *)pblock_list[i].pbuf;

		if(pblock_list[i].ip->protocol != IPPROTO_TCP)
			continue;

		pblock_list[i].tcp = (struct tcphdr *)(((unsigned char *)pblock_list[i].ip) + (pblock_list[i].ip->ihl * 4));

		if(!pblock_list[i].tcp->syn)
			continue;
				
		if (pblock_list[i].ip->daddr != daddr )
			continue;

		#ifdef DEBUG
			printf("The REAL SYN change status from KEEP to SEND\n");
		#endif

		pblock_list[i].status = SEND;
	}
}

/* 
 * enque_ttl_probe has not the intelligence to understand if TTL bruteforcing 
 * is required or not more. Is called in different section of code
 */
void TCPTrack::enque_ttl_probe( struct packetblock *delayed_syn_pkt, struct sniffjoke_track *ct)
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

	injpb->ip = (struct iphdr *)injpb->pbuf;
	injpb->tcp = (struct tcphdr *)(injpb->pbuf + (injpb->ip->ihl * 4) );

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
#ifdef DEBUG
	printf("Injecting probe %d, tested_ttl %d [exp %d min work %d], (dport %d sport %d) daddr %u\n", 
		ct->tf->sent_probe,
		tested_ttl, 
		ct->tf->expiring_ttl, ct->tf->min_working_ttl, 
		ntohs(injpb->tcp->dest), ntohs(injpb->tcp->source),
		injpb->ip->daddr
	);
#endif
}

struct ttlfocus *TCPTrack::init_ttl_focus(int first_free, unsigned int destip)
{
		if (first_free == -1) {
			maxttlfocus *= 2;
			ttlfocus_list = (struct ttlfocus *)realloc( 
				(void *)ttlfocus_list, 
				sizeof(struct ttlfocus) * maxttlfocus 
			);
			
			check_call_ret("memory allocation", errno, ttlfocus_list == NULL ? -1 : 0 );
			
			memset(	(void *)&ttlfocus_list[maxttlfocus / 2], 
				0x00, 
				(sizeof(struct ttlfocus) * maxttlfocus / 2)
			);
			
			printf("### memory allocation for ttlfocus_list in %s:%d:%s() new size: %d\n", __FILE__, __LINE__, __func__, maxttlfocus);
			
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
 * as reference for each conntrack with the some distination address. every session
 * had access in the some ttlfocus.
 * 
 * in ttlfocus are keep the informations for ttl bruteforcing
 */
struct ttlfocus *TCPTrack::find_ttl_focus(unsigned int destip, int initialize) 
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

unsigned int TCPTrack::half_cksum(void *pointed_data, int len)
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


void TCPTrack::fix_iptcp_sum(struct iphdr *iph, struct tcphdr *tcph)
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

unsigned int TCPTrack::make_pkt_id(struct iphdr *ip) 
{
	struct tcphdr *tcp;

	if(ip->protocol == IPPROTO_TCP) 
	{
		tcp = (struct tcphdr *)((unsigned char *)ip + (ip->ihl * 4));
		return tcp->seq;
	}
	else
		return 0; /* packet_id == 0 mean no ID check */
}

/* 
 * this two functions is required on hacking injection, because that 
 * injection should happens ALWAYS, but give the less possible elements
 * to the attacker for detects sniffjoke working style
 */
bool TCPTrack::percentage(float math_choosed, int vecna_choosed)
{
	return ( (random() % 100) <= ( (int)(math_choosed * vecna_choosed ) / 100 ) );
}

/*	the variable is used from the sniffjoke routing for decreete the possibility of
 *	an hack happens. this variable are mixed in probabiliy with the ct->packet_number, because
 *	the hacks must happens, for the most, in the start of the session (the first 10 packets),
 *	other hacks injection should happen in the randomic mode express in logarithm function.
 */
float TCPTrack::logarithm(int packet_number)
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

/* 
 * last packet fix! is the catch all for all packets, they should be:
 *   PRESCRIPTION pkt, that expire BEFORE REACH destination addr
 *   GUILTY pkt, that have some kind of error to be discarged from the dest
 *   INNOCENT pkt, valid packet that reach destination address
 *
 *   otherwise, the should be the packet received from the tunnel. They 
 *   use the some treatmen of INNOCENT packets.
 *
 *   at the moment, no hacks use INNOCENT flag.
 */
void TCPTrack::last_pkt_fix( struct packetblock *pkt)
{
#define STARTING_ARB_TTL 46
	unsigned char final_ttl;
	time_t now = time(NULL);
	int i;

	/* 
	 * packets different from TCP, and packets without ttl focus struct are
	 * send immediatly
	 */ 
#ifdef DEBUG
	if(pkt->proto == TCP) 
		printf("last_pkt_fix (TCP) : id %u (lo:%d %s:%d) proto %d source %d \n", 
			ntohs(pkt->ip->id), 
			ntohs(pkt->tcp->source),
			inet_ntoa( *((struct in_addr *)&pkt->ip->daddr) ) ,
			ntohs(pkt->tcp->dest), 
			pkt->ip->protocol, 
			pkt->source
		);
	else 
		printf("last_pkt_fix (!TCP): id %u proto %d source %d \n", 
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

		final_ttl = STARTING_ARB_TTL + (random() % 20);
	}
	else 
	{
		if(pkt->wtf == PRESCRIPTION) 
			final_ttl = pkt->tf->expiring_ttl; 
		else 	/* GUILTY or INNOCENT */
			final_ttl = (pkt->tf->expiring_ttl + (random() % 5) + 1 );
	}
	pkt->ip->ttl = final_ttl;

	/* 
	 * 2nd check: HOW MANY IP/TCP OPTIONS SET TO THE PACKET ?, the pbuf_size is
 	 * ready with "int variable_iptcpopt = (MAXOPTINJ * 3);" byte, in 
 	 * packet_orphanotrophy.
 	 */
	if( (! pkt->tcp->syn) && ntohs(pkt->ip->tot_len) < (MTU - 72) )
		if( percentage( 1, 100 ) )
			SjH__inject_ipopt( pkt );

	if( (!pkt->tcp->syn) && (!check_uncommon_tcpopt(pkt->tcp)) && pkt->wtf != INNOCENT )
		if( percentage( 25, 100 ) )
			SjH__inject_tcpopt( pkt );

	/* 3rd check: GOOD CHECKSUM or BAD CHECKSUM ? */
	fix_iptcp_sum(pkt->ip, pkt->tcp);

	if(pkt->wtf == GUILTY)
		pkt->tcp->check ^= (0xd34d * (unsigned short)random() +1);
}

bool TCPTrack::check_uncommon_tcpopt(struct tcphdr *tcp) 
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
TCPTrack::packet_orphanotrophy( struct iphdr *ip, struct tcphdr *tcp, int resize)
{
	struct packetblock *ret;
	int pbuf_size = 0;
	int iplen = ip->ihl * 4;
	int tcplen = tcp->doff * 4;
	int payload_len;
	int new_tot_len;
	int dptr = 0;

	/* 
	 * the packets generated could be resized, for the sniffjoke hack
 	 */
	switch(resize) 
	{
		case UNCHANGED_SIZE:
			pbuf_size = ntohs(ip->tot_len) + (MAXOPTINJ * 3);
			new_tot_len = ntohs(ip->tot_len);
 			payload_len = ntohs(ip->tot_len) - ( iplen + tcplen );
			break;
		case 0:
			pbuf_size = iplen + tcplen + (MAXOPTINJ * 3);
			new_tot_len = iplen + tcplen;
 			payload_len = 0; 
			break;
		default:
			pbuf_size = iplen + tcplen + (MAXOPTINJ * 3) + resize;
			new_tot_len = iplen + tcplen + resize;
 			payload_len = resize; 
	}
	
	ret = get_free_pblock( pbuf_size, HIGH, 0);

	ret->packet_id = 0;
	ret->proto = TCP;
	ret->source = LOCAL;
	ret->status = SEND;
	ret->orig_pktlen = ntohs(ip->tot_len);

	/* IP header copy */
	memcpy(&ret->pbuf[dptr], (void *)ip, iplen);
	ret->ip = (struct iphdr *)&ret->pbuf[dptr];
	dptr = iplen;

	/* TCP header copy */
	memcpy(&ret->pbuf[dptr], (void *)tcp, tcplen );
	ret->tcp = (struct tcphdr *)&ret->pbuf[dptr];
	dptr += tcplen;

	/* Payload copy, if preserved */
	if(payload_len) 
		memcpy(&ret->pbuf[dptr], (unsigned char *)ip + (iplen + tcplen), payload_len);

	/* fixing the new length */
	ret->ip->tot_len = htons(new_tot_len);

	return ret;
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
void TCPTrack::SjH__fake_data( struct packetblock *hackp)
{
	int i, diff;
	unsigned char *payload;

	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));

	payload = (unsigned char *)hackp->ip + (hackp->ip->ihl * 4) + (hackp->tcp->doff * 4);
	diff = ntohs(hackp->ip->tot_len) - ( (hackp->ip->ihl * 4) + (hackp->tcp->doff * 4) );

	for(i = 0; i < (diff -3); i += 4)
		*(unsigned int *)(&payload[i]) = random();
}

void TCPTrack::SjH__fake_seq( struct packetblock *hackp)
{
	int payload = ntohs(hackp->ip->tot_len) - ( (hackp->ip->ihl * 4) + (hackp->tcp->doff * 4) );
	int what = (random() % 3);

	/* 
	 * MAXOPTINJ is used * 3 because the packet can be incremented in size here,
	 * have ipopt and tcpopt. This variable should, and is better if became random
	 * instead of fixed value.
	 */
	if( !payload ) {
		hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) + MAXOPTINJ);
		hackp->ip->tot_len = htons(ntohs(hackp->ip->tot_len) + MAXOPTINJ);

	}
	else
		if(what == 0)
			what =2;

	if(what == 2) 
		hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) + (random() % 5000));

	if(what == 1)
		hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) - (random() % 5000));

	hackp->tcp->window = htons((random() % 80) * 64);
	hackp->tcp->ack = 0;
	hackp->tcp->ack_seq = 0;

	SjH__fake_data(hackp);
}

void TCPTrack::SjH__valid_rst_fake_seq( struct packetblock *hackp)
{
	/* 
 	 * if the session is resetted, the remote box maybe vulnerable to:
 	 * Slipping in the window: TCP Reset attacks
 	 * http://kerneltrap.org/node/3072
 	 */
	hackp->tcp->seq = htonl(ntohl(hackp->tcp->seq) + 65535 + (random() % 12345));
	hackp->tcp->window = (unsigned short)(-1);
	hackp->tcp->rst = hackp->tcp->ack = 1;
	hackp->tcp->ack_seq = htonl(ntohl(hackp->tcp->seq + 1));
	hackp->tcp->fin = hackp->tcp->psh = hackp->tcp->syn = 0;
	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));
}

/* fake syn, some more or less value, but, fake */
void TCPTrack::SjH__fake_syn( struct packetblock *hackp)
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

void TCPTrack::SjH__shift_ack( struct packetblock *hackp)
{
	hackp->tcp->ack_seq = htonl(ntohl(hackp->tcp->ack_seq) + 65535 );
	hackp->ip->id = htons(ntohs(hackp->ip->id) + (random() % 10));
}

void TCPTrack::SjH__fake_close( struct packetblock *hackp)
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

void TCPTrack::SjH__zero_window( struct packetblock *hackp)
{
	hackp->tcp->syn = hackp->tcp->fin = hackp->tcp->rst = 1;
	hackp->tcp->psh = hackp->tcp->ack = 0;
	hackp->tcp->window = 0;
}

void TCPTrack::SjH__inject_ipopt( struct packetblock *hackp )
{
	int iplen = (hackp->ip->ihl * 4);
	int l47len, i = 0, x = 0;
	int route_n = (random() % 5) + 5; /* 5 - 9 */
	unsigned char *endip = hackp->pbuf + sizeof(struct iphdr);

	/* l47len = length of the frame layer 4 to 7 */
	l47len = ntohs(hackp->ip->tot_len) - (hackp->ip->ihl * 4);

	/* 1: strip the original ip options, if present */	
	if( iplen > sizeof(struct iphdr )) 
	{
		memmove(endip, endip + (iplen - sizeof(struct iphdr)), l47len);

		l47len = ntohs(hackp->ip->tot_len) - sizeof(struct iphdr);
		iplen = sizeof(struct iphdr);
	}

	/* 2: shift the tcphdr and the payload byte after the reserved space to IPOPT_RR */
	memmove(endip + ( (route_n + 1) * 4), endip, l47len);
	hackp->tcp = (struct tcphdr *)(hackp->pbuf + sizeof(struct iphdr) + ( (route_n + 1) * 4) );
	hackp->ip = (struct iphdr *)hackp->pbuf;

	endip[i++] = IPOPT_NOP;
	endip[i++] = IPOPT_RR;
	endip[i++] = (route_n * 4) + 3;
	endip[i++] = 4;

	for(x = i; x != (route_n * 4); x += 4 ) {
		unsigned int randip = random();
		memcpy(&endip[x], &randip, 4);
	}

#ifdef HACKSDEBUG
	printf("Inj IpOpt (lo:%d %s:%d) (route_n %d) id %u l47 %d tot_len %d -> %d {%d%d%d%d%d}\n",
		ntohs(hackp->tcp->source), 
		inet_ntoa( *((struct in_addr *)&hackp->ip->daddr) ) ,
		ntohs(hackp->tcp->dest), 
		route_n,
		ntohs(hackp->ip->id),
		l47len,
		ntohs(hackp->ip->tot_len),
		(iplen + ( (route_n + 1) * 4) +  l47len),
		hackp->tcp->syn, hackp->tcp->ack, hackp->tcp->psh, hackp->tcp->fin, hackp->tcp->rst
	);
#endif
	hackp->ip->ihl = 15; /* 20 byte ip hdr, 40 byte options */
	hackp->ip->tot_len = htons(60 + l47len);
}

void TCPTrack::SjH__inject_tcpopt( struct packetblock *hackp ) 
{
	int hdrlen = (hackp->ip->ihl * 4) + sizeof(struct tcphdr);
	int payload_len = ntohs(hackp->ip->tot_len) - (hackp->ip->ihl * 4) - (hackp->tcp->doff * 4);
	int faketcpopt = 8;
	unsigned char *endtcp = &hackp->pbuf[hdrlen];
	int startopt = (hackp->tcp->doff * 4) - sizeof(struct tcphdr);
	int i = 0;
	time_t now = time(NULL);

	/* 1: strip the original tcp options, copying payload over */
	memmove(endtcp, endtcp + startopt, payload_len);
	/* 2: shift the payload to the wfaketcpopt offset */
	memmove(endtcp + faketcpopt, endtcp, payload_len);

	endtcp[i++] = TCPOPT_NOP;
	endtcp[i++] = TCPOPT_NOP;
	endtcp[i++] = TCPOPT_TIMESTAMP;
	endtcp[i++] = 6; // TCPOLEN_TIMESTAMP; /* 10, but invalid! */

	/* time_t, 4 byte of time stamp value */
	memcpy(&endtcp[i], &now, sizeof(now));

#ifdef HACKSDEBUG
	printf("Fake TcpOpt (lo:%d %s:%d) id %u hdr %d payload %d tot_len %d -> %d {%d%d%d%d%d}\n",
		ntohs(hackp->tcp->source), 
		inet_ntoa( *((struct in_addr *)&hackp->ip->daddr) ) ,
		ntohs(hackp->tcp->dest), 
		ntohs(hackp->ip->id),
		hdrlen, payload_len,
		ntohs(hackp->ip->tot_len),
		(hdrlen + faketcpopt + payload_len),
		hackp->tcp->syn, hackp->tcp->ack, hackp->tcp->psh, hackp->tcp->fin, hackp->tcp->rst
	);
#endif
	hackp->tcp->doff = (sizeof(struct tcphdr) + 2) & 0xf;
	hackp->ip->tot_len = htons(hdrlen + faketcpopt + payload_len);
}
