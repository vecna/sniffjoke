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
#include "sj_packet.h"
#include "sj_utils.h"

Packet::Packet(const unsigned char* buff, int size) :
	packet_id(make_pkt_id(buff)),
	source(SOURCEUNASSIGNED),
	status(STATUSUNASSIGNED),
	wtf(JUDGEUNASSIGNED),
	proto(PROTOUNASSIGNED),
	injection(ANY_INJECTION),
        pbuf(size)
{
	memcpy(&(pbuf[0]), buff, size);
	updatePointers();
	
	orig_pktlen = ntohs(ip->tot_len);
}

Packet::Packet(const Packet& pkt) :
	packet_id(0),
	evilbit(GOOD),
	source(SOURCEUNASSIGNED),
	status(STATUSUNASSIGNED),
	wtf(JUDGEUNASSIGNED),
	proto(PROTOUNASSIGNED),
	pbuf(pkt.pbuf),
	orig_pktlen(pkt.orig_pktlen)
{
	updatePointers();
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

void Packet::mark(source_t source, status_t status, judge_t judge)
{
	this->source = source;
	this->status = status;
	this->wtf = judge;
}

void Packet::updatePointers(void)
{
	ip = (struct iphdr *)&(pbuf[0]);
	if (ip->protocol == IPPROTO_TCP) {
		proto = TCP;
		tcp = (struct tcphdr *)((unsigned char *)(ip) + (ip->ihl * 4));
		icmp = NULL;
		if ((ntohs(ip->tot_len) - ((ip->ihl * 4) + (tcp->doff * 4))) > 0)
			payload = (unsigned char *)tcp + tcp->doff * 4;
		else
			payload = NULL;
	} else if (ip->protocol == IPPROTO_ICMP) {
		proto = ICMP;
		tcp = NULL;
		icmp = (struct icmphdr *)((unsigned char *)(ip) + (ip->ihl * 4));
		payload = NULL;
	} else {
		proto = OTHER_IP;
		tcp = NULL;
		icmp = NULL;
		payload = NULL;
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
	unsigned int l4len = ntohs(ip->tot_len) - (ip->ihl * 4);

	ip->check = 0;
	sum = half_cksum((const void *)ip, (ip->ihl * 4));
	ip->check = compute_sum(sum);
	tcp->check = 0;
	sum = half_cksum((const void *) &ip->saddr, 8);
	sum += htons (IPPROTO_TCP + l4len);
	sum += half_cksum((const void *)tcp, l4len);
	tcp->check = compute_sum(sum);
}

void Packet::increasePbuf(unsigned int morespace)
{
	/* the pbuf can only be incremented safaly, not decremented */
	pbuf.resize(pbuf.size() + morespace);
	
	updatePointers();
}

void Packet::resizePayload(unsigned int newlen) 
{
	/* the payload can be incremented or decremented safely */
	int iphlen = ip->ihl * 4;
	int tcphlen = tcp->doff * 4;
	int oldlen = ntohs(ip->tot_len) - (iphlen + tcphlen);
	unsigned int newpbuf_size = pbuf.size() - oldlen + newlen;
	vector<unsigned char> newpbuf = vector<unsigned char>(newpbuf_size, 0);
	unsigned newtotallen = iphlen + tcphlen + newlen;
	
	/* IP header copy , TCP header copy, Payload copy, if preserved */
	int copysize = newtotallen > ntohs(ip->tot_len) ? ntohs(ip->tot_len) : newtotallen;
	memcpy(&(newpbuf[0]), &(pbuf[0]), copysize );
	pbuf = newpbuf;

        ip = (struct iphdr *)&(pbuf[0]);
        ip->tot_len = htons(newtotallen);

	updatePointers();
}

void Packet::fillRandomPayload()
{
	const unsigned diff = ntohs(ip->tot_len) - ((ip->ihl * 4) + (tcp->doff * 4));
	memset_random(payload, diff);
}

/* ipopt IPOPT_RR inj*/
void Packet::SjH__inject_ipopt(void)
{
	const int route_n = random() % 10;
	const unsigned fakeipopt = ((route_n + 1) * 4);
	const int needed_space = fakeipopt;
	const int free_space = pbuf.size() - ntohs(ip->tot_len);
	
	int iphlen = ip->ihl * 4;
	int tcphlen = tcp->doff * 4;
	const int l47len = ntohs(ip->tot_len) - iphlen;
		
	if(free_space < needed_space) {
		/* safety ip size check */
		if(iphlen + needed_space > 60)
			return;
			
		increasePbuf(needed_space - free_space);
	}
	
	unsigned char *endip = (unsigned char*)&pbuf[0] + iphlen;

	iphlen += fakeipopt;

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

	memset_random(&endip[4], fakeipopt - 4);

	ip->ihl = iphlen / 4;
	ip->tot_len = htons(iphlen + l47len);
	tcp = (struct tcphdr *)((unsigned char*)(ip) + iphlen);
	payload = (unsigned char *)(tcp) + tcphlen;
}


/* tcpopt TCPOPT_TIMESTAMP inj with bad TCPOLEN_TIMESTAMP */
void Packet::SjH__inject_tcpopt(void)
{
	const int faketcpopt = 4;
	const int needed_space = faketcpopt;
	const int free_space = pbuf.size() - ntohs(ip->tot_len);

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
}

HackPacket::HackPacket(const Packet& pkt, const char* hackname) :
	Packet(pkt),
	debug_info(hackname),
	position(ANTICIPATION),
	prejudge(GUILTY_OR_PRESCRIPTION),
	prescription_probability(93),
	hack_frequency(0)
{
	packet_id = 0;
	evilbit = EVIL;
}
