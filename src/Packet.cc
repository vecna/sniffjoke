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

#include "Packet.h"
#include "HDRoptions.h"

Packet::Packet(const unsigned char* buff, int size) :
	prev(NULL),
	next(NULL),
	packet_id(make_pkt_id(buff)),
	evilbit(MORALITYUNASSIGNED),
	source(SOURCEUNASSIGNED),
	status(STATUSUNASSIGNED),
	wtf(JUDGEUNASSIGNED),
	proto(PROTOUNASSIGNED),
	position(POSITIONUNASSIGNED),
	pbuf(size),
        ip(NULL),
        tcp(NULL),
        payload(NULL),
        icmp(NULL)
{
	if(check_evil_packet(buff, size) == false)
		throw exception();

	memcpy(&(pbuf[0]), buff, size);
	updatePacketMetadata();
	
	memset(debugbuf, 0x00, LARGEBUF);
}

Packet::Packet(const Packet& pkt) :
	prev(NULL),
	next(NULL),
	packet_id(0),
	evilbit(MORALITYUNASSIGNED),
	source(SOURCEUNASSIGNED),
	status(STATUSUNASSIGNED),
	wtf(JUDGEUNASSIGNED),
	proto(PROTOUNASSIGNED),
	position(POSITIONUNASSIGNED),
        pbuf(pkt.pbuf),
        ip(NULL),
        tcp(NULL),
        payload(NULL),
        icmp(NULL)
{
	updatePacketMetadata();
	memset(debugbuf, 0x00, LARGEBUF);
}

unsigned int Packet::make_pkt_id(const unsigned char* buf) const
{
	struct iphdr *ip = (struct iphdr *)buf;
	struct tcphdr *tcp;
	if (ip->protocol == IPPROTO_TCP) {
		tcp = (struct tcphdr *)((unsigned char *)(ip) + (ip->ihl * 4));
		return tcp->seq;
	} else
		return 0; /* packet_id == 0 mean no ID check */
}

void Packet::mark(source_t source, status_t status, evilbit_t morality)
{
	this->source = source;
	this->status = status;
	this->evilbit = morality;
}

void Packet::mark(source_t source, status_t status, judge_t wtf, evilbit_t morality) {
	this->wtf = wtf;
	mark(source, status, morality);
}

void Packet::updatePacketMetadata(void)
{
	ip = (struct iphdr *)&(pbuf[0]);
	iphdrlen = (ip->ihl * 4);
	pktlen = ntohs(ip->tot_len);
	
	tcp = NULL;
	tcphdrlen = 0;
	payload = NULL;
	datalen = 0;
	icmp = NULL;

	if (ip->protocol == IPPROTO_TCP) {
		proto = TCP;

		tcp = (struct tcphdr *)((unsigned char *)(ip) + iphdrlen);
		tcphdrlen = tcp->doff * 4;

		datalen = ntohs(ip->tot_len) - iphdrlen - tcphdrlen;
		if(datalen)
			payload = (unsigned char *)tcp + tcphdrlen;
		else
			payload = NULL;

	} else if (ip->protocol == IPPROTO_ICMP) {
		proto = ICMP;
		icmp = (struct icmphdr *)((unsigned char *)(ip) + iphdrlen);
	} else {
		proto = OTHER_IP;
	}
}

unsigned int Packet::half_cksum(const void* data, int len)
{
	const unsigned short *usdata = (const unsigned short *)data;
	unsigned int sum = 0;

	while (len > 1)
	{
		sum += *usdata++;
		if(sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len == 1)
		sum += (unsigned short) *(unsigned char*)usdata;

	return sum;
}

unsigned short Packet::compute_sum(unsigned int sum)
{
	while(sum>>16)
             sum = (sum & 0xFFFF) + (sum >> 16);

	return (unsigned short) ~sum;
}

void Packet::fixIpTcpSum(void)
{
	unsigned int sum;
	unsigned int l4len = ntohs(ip->tot_len) - iphdrlen;

	ip->check = 0;
	sum = half_cksum((const void *)ip, iphdrlen);
	ip->check = compute_sum(sum);
	tcp->check = 0;
	sum = half_cksum((const void *) &ip->saddr, 8);
	sum += htons (IPPROTO_TCP + l4len);
	sum += half_cksum((const void *)tcp, l4len);
	tcp->check = compute_sum(sum);
}

bool Packet::SelfIntegrityCheck(const char *pluginName)
{
	if(source != SOURCEUNASSIGNED ) {
		debug.log(ALL_LEVEL, "SelfIntegrityCheck: in %s (source_t)source must not be set: ignored value", pluginName);
	}

	if(status != STATUSUNASSIGNED ) {
		debug.log(ALL_LEVEL, "SelfIntegrityCheck: in %s (status_t)status must not be set: ignored value", pluginName);
	}

	if(wtf == JUDGEUNASSIGNED ) {
		debug.log(ALL_LEVEL, "SelfIntegrityCheck: in %s not set \"wtf\" field (what the fuck Sj has to do with this packet?)", pluginName);
		goto errorinfo;
	}

	if(proto == PROTOUNASSIGNED) {
		debug.log(ALL_LEVEL, "SelfIntegrityCheck: in %s not set \"proto\" field, required", pluginName);
		goto errorinfo;
	}

	if(position == POSITIONUNASSIGNED) {
		debug.log(ALL_LEVEL, "SelfIntegrityCheck: in %s not set \"position\" field, required", pluginName);
		goto errorinfo;
	}

	return true;

errorinfo:
	debug.log(DEBUG_LEVEL, "Documentation about plugins development: http://www.sniffjoke.net/delirandom/plugins");
	return false;
}

void Packet::increasePbuf(unsigned int morespace)
{
	/* the pbuf can only be incremented safaly, not decremented */
	pbuf.resize(pbuf.size() + morespace);
	
	updatePacketMetadata();
}

void Packet::resizePayload(unsigned int newlen) 
{
	/* the payload can be incremented or decremented safely */
	int oldlen = ntohs(ip->tot_len) - (iphdrlen + tcphdrlen);
	unsigned int newpbuf_size = pbuf.size() - oldlen + newlen;
	vector<unsigned char> newpbuf = vector<unsigned char>(newpbuf_size, 0);
	
	/* IP header copy , TCP header copy, Payload copy, if preserved */
	int copysize = newpbuf_size > ntohs(ip->tot_len) ? ntohs(ip->tot_len) : newpbuf_size;
	memcpy(&(newpbuf[0]), &(pbuf[0]), copysize );
	pbuf = newpbuf;

        ip = (struct iphdr *)&(pbuf[0]);
        ip->tot_len = htons(newpbuf_size);

	updatePacketMetadata();
}

void Packet::fillRandomPayload()
{
	const unsigned diff = ntohs(ip->tot_len) - (iphdrlen + tcphdrlen);
	memset_random(payload, diff);
}


bool Packet::checkUncommonTCPOPT()
{
	unsigned char check;
	/* default: there are not uncommon TCPOPT, and the packets should be stripped off */
	bool ret = false ;

	for (unsigned int i = sizeof(struct tcphdr); i < tcphdrlen; i++)
	{
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
		default:
			ret = true; break;
		/* every unknow TCPOPT is keep, only TIMESTAMP, EOL, NOP are stripped off ATM */
		}
	}

	if(ret)
		selflog(__func__, "ARE present!");

	return ret;
}

/* ATM not implemented: false = there are not uncommon ip opt */
bool Packet::checkUncommonIPOPT() {
	return false;
}

void Packet::IPHDR_shift(unsigned int sizetogive) 
{
	/* it happen when new ipoptions need to be addedd */
	if(iphdrlen < sizetogive) {
		increasePbuf(sizetogive - iphdrlen);
		memmove(&pbuf[sizetogive], &pbuf[iphdrlen], pktlen - iphdrlen + sizetogive);
	}
	else if(iphdrlen == sizetogive) {
	}
	else /* iphdrlen > sizetogive */ {
		memmove(&ip[iphdrlen], &ip[sizetogive], pktlen - sizetogive + iphdrlen);
	}
	ip->ihl = (sizetogive / 4);
}

void Packet::TCPHDR_shift(unsigned int sizetogive) 
{
	unsigned char *tcp_ptr = (unsigned char *)tcp;

	if(tcphdrlen < sizetogive) 
	{
		increasePbuf(sizetogive - tcphdrlen);

		if(datalen)
			memmove(&tcp_ptr[sizetogive], &tcp_ptr[tcphdrlen], pktlen - tcphdrlen + sizetogive);
	}
	else if(tcphdrlen == sizetogive) {
	}
	else /* tcphdrlen > sizetogive */ {
		memmove(&tcp_ptr[tcphdrlen], &tcp[sizetogive], pktlen - sizetogive + tcphdrlen);
	}
	tcp->doff = (sizetogive / 4);
}

/* called by TCPTrack.cc */
void Packet::Inject_IPOPT(bool corrupt, bool strip_previous)
{
	if(strip_previous && iphdrlen != sizeof(struct iphdr)) {
		memmove(&pbuf[sizeof(struct iphdr)], (unsigned char *)tcp, tcphdrlen + datalen);
		iphdrlen = sizeof(struct iphdr);
		ip->ihl = iphdrlen / 4;
	}

	/* VERIFY - TODO: randomize the dimension of the injection */
	unsigned int target_iphdrlen = 40;

	IPHDR_shift(target_iphdrlen);

	/* used to keep track of header growing */
	unsigned int actual_iphdrlen = 0; 

	HDRoptions IPInjector( (unsigned char *)ip + sizeof(struct iphdr), iphdrlen, target_iphdrlen);
	int MAXITERATION = 10;

	do {
		actual_iphdrlen = IPInjector.randomInjector(corrupt);

	} while( target_iphdrlen != actual_iphdrlen && --MAXITERATION );
}



/* called by TCPTrack.cc */
#if 0
void Packet::Inject_TCPOPT(bool corrupt, bool strip_previous)
{
	if(strip_previous && iphdrlen != sizeof(struct iphdr)) 
	{
		if(datalen)
			memmove(&pbuf[iphdrlen + sizeof(struct tcphdr)], payload, datalen);

		tcphdrlen = sizeof(struct tcphdr);
		tcp->doff = tcphdrlen / 4;
	}

	/* VERIFY - TODO: randomize the dimension of the injection */
	unsigned int actual_tcphdrlen, target_tcphdrlen = 40;

	HDRoptions TCPInjector( (unsigned char *)tcp + sizeof(struct tcphdr), tcphdrlen, target_tcphdrlen);
	int MAXITERATION = 6;

	do {
		actual_tcphdrlen += TCPInjector.randomInjector(corrupt);

	} while( target_tcphdrlen != actual_tcphdrlen && --MAXITERATION ); 
}
#endif

#if 0 // OLD - use as reference and delete 
/* tcpopt TCPOPT_TIMESTAMP inj with bad TCPOLEN_TIMESTAMP */
void Packet::Inject_BAD_TCPOPT(void)
{
	const int faketcpopt = 4;
	const int needed_space = faketcpopt;
	const int free_space = pbuf.size() - ntohs(ip->tot_len);

	selflog(__func__, "before TCPopt injection");

	int iphlen = ip->ihl * 4;
	int tcphlen = tcp->doff * 4;
	const int l57len = ntohs(ip->tot_len) - (iphlen + tcphlen);

	if(free_space < needed_space) {

		/* safety ip size check */
		if(tcphlen + needed_space > 60)
			return;

		increasePbuf(needed_space - free_space);
	}

	unsigned char *endtcp = (unsigned char*)&pbuf[0] + iphlen + tcphlen;

	tcphlen += faketcpopt;
	
	/* 2: shift the payload after the reserved space to faketcpopt */
	memmove(endtcp + faketcpopt, endtcp, l57len);

	endtcp[0] = TCPOPT_NOP;
	endtcp[1] = TCPOPT_NOP;
	endtcp[2] = TCPOPT_TIMESTAMP;
	endtcp[3] = random() % 11;

	/*
	 *  from: /usr/include/netinet/tcp.h:
	 *  # define TCPOLEN_TIMESTAMP	  10
	 *  reserved for: NOP (1),
	                  NOP (1),
	                  TCPOPT_TIMESTAMP (1),
	                  TCPOPT_LEN (1),
	                  Timestamp Value (TSval) (4),
	                  Timestamp Echo Reply (TSecr) (4)
	 * 
	 *  so the hacks are two:
	 *   - the size indicated could be different than 10
	 *   - there is no space reserved for timestamps
	 */ 

	ip->tot_len = htons(iphlen + tcphlen + l57len);
	tcp->doff = tcphlen / 4;
	payload = (unsigned char *)(tcp) + tcphlen;

	selflog(__func__, "after TCPopt injection");
}
#endif

void Packet::selflog(const char *func, const char *loginfo) 
{
	const char *evilstr, *statustr, *wtfstr, *sourcestr;
	char *p, protoinfo[MEDIUMBUF]; 

	/* inet_ntoa use a static buffer */
	char saddr[MEDIUMBUF], daddr[MEDIUMBUF];

	p = inet_ntoa(*((struct in_addr *)&(ip->saddr)));
	strncpy(saddr, p, MEDIUMBUF);

	p = inet_ntoa(*((struct in_addr *)&(ip->daddr)));
	strncpy(daddr, p, MEDIUMBUF);

	switch(evilbit) {
		case GOOD: evilstr = "good"; break;
		case EVIL: evilstr = "evil"; break;
                default: case MORALITYUNASSIGNED: evilstr = "unassigned evilbit"; break;

	}

	switch(status) {
		case YOUNG:  statustr = "young"; break;
		case SEND: statustr = "send"; break;
		case KEEP: statustr = "keep"; break;
                default: case STATUSUNASSIGNED: statustr = "unassigned status"; break;
	}

	switch(wtf) {
		case RANDOMDAMAGE: wtfstr ="everybad"; break;
		case PRESCRIPTION: wtfstr ="prescript"; break;
		case INNOCENT: wtfstr ="innocent"; break;
		case GUILTY: wtfstr ="badcksum"; break;
		case MALFORMED: wtfstr ="malformetIP"; break;
                default: case JUDGEUNASSIGNED: wtfstr = "unassigned wtf"; break;
	}

	switch(source) {
		case TUNNEL: sourcestr = "tunnel"; break;
		case LOCAL: sourcestr = "local"; break;
		case NETWORK: sourcestr = "network"; break;
		case TTLBFORCE: sourcestr = "ttl force"; break;
		default: case SOURCEUNASSIGNED: sourcestr = "unassigned source"; break;
	}

	memset(protoinfo, 0x0, MEDIUMBUF);
	switch(proto) {
		case TCP:
			snprintf(protoinfo, MEDIUMBUF, "[TCP sp %d dp %d SAFR{%d%d%d%d} len %d(%d) seq %x ack_seq %x]",
				ntohs(tcp->source), ntohs(tcp->dest), tcp->syn, tcp->ack, tcp->fin, 
				tcp->rst, pktlen, pktlen - iphdrlen - tcphdrlen, 
				ntohl(tcp->seq), ntohl(tcp->ack_seq)
			);
			break;
		case ICMP:
			snprintf(protoinfo, MEDIUMBUF, "ICMP type %d code %d len %d(%d)",
				icmp->type, icmp->code,
				pktlen, (int)(pktlen - iphdrlen - sizeof(struct icmphdr))
			);
			break;
		case OTHER_IP:
			snprintf(protoinfo, MEDIUMBUF, "Other proto: %d", ip->protocol);
			break;
		case PROTOUNASSIGNED:
			snprintf(protoinfo, MEDIUMBUF, "protocol unassigned! value %d", ip->protocol);
			break;
		default: case ANY_PROTO:
			debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
			SJ_RUNTIME_EXCEPTION();
			break;
	}

	debug.log(PACKETS_DEBUG, "%s :%x: E|%s status %s WTF|%s src %s|%s->%s proto [%s] ttl %d %s",
		func, packet_id, evilstr, statustr, wtfstr, sourcestr,
		saddr, daddr,
		protoinfo, ip->ttl, loginfo
       	);

	memset(debugbuf, 0x00, LARGEBUF);
}


bool Packet::check_evil_packet(const unsigned char *buff, unsigned int nbyte)
{
	struct iphdr *ip = (struct iphdr *)buff;
 
	if (nbyte < sizeof(struct iphdr) || nbyte < ntohs(ip->tot_len) ) {
		debug.log(PACKETS_DEBUG, "%s %s: nbyte %s < (struct iphdr) %d || (ip->tot_len) %d", 
			__FILE__, __func__, nbyte, sizeof(struct iphdr), ntohs(ip->tot_len)
		);
		return false;
	}

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp;
		int iphlen;
		int tcphlen;

		iphlen = ip->ihl * 4;

		if (nbyte < iphlen + sizeof(struct tcphdr)) {
			debug.log(PACKETS_DEBUG, "%s %s: [bad TCP] nbyte %d < iphlen + (struct tcphdr) %d",
				__FILE__, __func__, nbyte, iphlen + sizeof(struct tcphdr)
			);
			return false;
		}

		tcp = (struct tcphdr *)((unsigned char *)ip + iphlen);
		tcphlen = tcp->doff * 4;
		
		if (ntohs(ip->tot_len) < iphlen + tcphlen) {
			debug.log(PACKETS_DEBUG, "%s %s: [bad TCP][bis] nbyte %d < iphlen + tcphlen %d",
				__FILE__, __func__, nbyte, iphlen + tcphlen
			);
			return false;
		}
	}
	return true;
}
