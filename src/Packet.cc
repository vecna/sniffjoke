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

#define MAXIPHEADER 60
#define MAXTCPHEADER 60

Packet::Packet(const unsigned char* buff, uint16_t size) :
	queue(QUEUEUNASSIGNED),
	prev(NULL),
	next(NULL),
	evilbit(MORALITYUNASSIGNED),
	source(SOURCEUNASSIGNED),
	wtf(JUDGEUNASSIGNED),
	proto(PROTOUNASSIGNED),
	position(POSITIONUNASSIGNED),
	pbuf(size),
        ip(NULL),
        iphdrlen(0),
        ipfragment(false),
        tcp(NULL),
        tcphdrlen(0),
        payload(NULL),
        datalen(0),
        icmp(NULL)
{
	memcpy(&(pbuf[0]), buff, size);
	updatePacketMetadata();
	
	memset(debug_buf, 0x00, sizeof(debug_buf));
}

Packet::Packet(const Packet& pkt) :
	queue(QUEUEUNASSIGNED),
	prev(NULL),
	next(NULL),
	evilbit(MORALITYUNASSIGNED),
	source(SOURCEUNASSIGNED),
	wtf(JUDGEUNASSIGNED),
	proto(PROTOUNASSIGNED),
	position(POSITIONUNASSIGNED),
        pbuf(pkt.pbuf),
        ip(NULL),
        iphdrlen(0),
        ipfragment(false),
        tcp(NULL),
        tcphdrlen(0),
        payload(NULL),
        datalen(0),
        icmp(NULL)
{
	updatePacketMetadata();
	memset(debug_buf, 0x00, sizeof(debug_buf));
}

void Packet::mark(source_t source, evilbit_t morality)
{
	this->source = source;
	this->evilbit = morality;
}

void Packet::mark(source_t source, judge_t wtf, evilbit_t morality) {
	this->wtf = wtf;
	mark(source, morality);
}

void Packet::updatePacketMetadata()
{	
	uint16_t pktlen = pbuf.size();
	
	/* start initial metadata reset */
	ip = NULL;
	iphdrlen = 0; 
	tcp = NULL;
	tcphdrlen = 0;
	payload = NULL;
	datalen = 0;
	icmp = NULL;
	/* end initial metadata reset */

	/* start ip update */
	if (pktlen < sizeof(struct iphdr))
		SJ_RUNTIME_EXCEPTION("pktlen < sizeof(struct iphdr)");

	ip = (struct iphdr *)&(pbuf[0]);
	iphdrlen = ip->ihl * 4;

	if (pktlen < iphdrlen)
		SJ_RUNTIME_EXCEPTION("pktlen < iphdrlen");
	
	
	if (pktlen < ntohs(ip->tot_len))
		SJ_RUNTIME_EXCEPTION("pktlen < ntohs(ip->tot_len)");
	/* end ip update */

	switch(ip->protocol) {
		case IPPROTO_TCP:
			proto = TCP;
			break;
		case IPPROTO_ICMP: 
			proto = ICMP;
			break;
		default:
			proto = OTHER_IP;
			break;
	}

	/* 
	 * at the time sniffjoke does not handle hacks on ip fragments.
	 * so we use a fragment variable to deny hacks application.
	 * there is also the need to bypass some checks in this function.
	 */
	if (ip->frag_off & htons(0x3FFF)) {
		ipfragment = true;
		return;
	}

	switch(ip->protocol) {
		case IPPROTO_TCP:
			/* start tcp update */
			if (pktlen < iphdrlen + sizeof(struct tcphdr))
				SJ_RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct tcphdr)");

			tcp = (struct tcphdr *)((unsigned char *)(ip) + iphdrlen);
			tcphdrlen = tcp->doff * 4;
			
			if (pktlen < iphdrlen + tcphdrlen)
				SJ_RUNTIME_EXCEPTION("pktlen < iphdrlen + tcphdrlen");

			datalen = pktlen - iphdrlen - tcphdrlen;
			if (datalen)
				payload = (unsigned char *)tcp + tcphdrlen;
			/* end tcp update */
			break;
		case IPPROTO_ICMP: 
			/* start icmp update */
			if (pktlen < iphdrlen + sizeof(struct icmphdr))
				SJ_RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct icmphdr)");

			icmp = (struct icmphdr *)((unsigned char *)(ip) + iphdrlen);
			/* end icmp update */
			
			break;
	}
}

uint32_t Packet::half_cksum(const void* data, uint16_t len)
{
	const uint16_t *usdata = (uint16_t *)data;
	const uint16_t *end = (uint16_t *)data + (len / sizeof(uint16_t));
	uint32_t sum = 0;

	while (usdata != end)
		sum += *usdata++;

	if (len % 2)
		sum += *(uint8_t *)usdata;

	return sum;
}

uint16_t Packet::compute_sum(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return ~sum;
}

void Packet::fixIpSum(void)
{
	uint32_t sum;

	ip->check = 0;
	sum = half_cksum((const void *)ip, iphdrlen);
	ip->check = compute_sum(sum);
}

void Packet::fixIpTcpSum(void)
{
	fixIpSum();

	uint32_t sum;
	const uint16_t l4len = ntohs(ip->tot_len) - iphdrlen;

	tcp->check = 0;
	sum = half_cksum((const void *) &ip->saddr, 8);
	sum += htons (IPPROTO_TCP + l4len);
	sum += half_cksum((const void *)tcp, l4len);
	tcp->check = compute_sum(sum);
}

bool Packet::selfIntegrityCheck(const char *pluginName)
{
	if (source != SOURCEUNASSIGNED) {
		debug.log(ALL_LEVEL, "selfIntegrityCheck: in %s (source_t)source must not be set: ignored value", pluginName);
	}

	if (wtf == JUDGEUNASSIGNED) {
		debug.log(ALL_LEVEL, "selfIntegrityCheck: in %s not set \"wtf\" field (what the fuck Sj has to do with this packet?)", pluginName);
		goto errorinfo;
	}

	if (proto == PROTOUNASSIGNED) {
		debug.log(ALL_LEVEL, "selfIntegrityCheck: in %s not set \"proto\" field, required", pluginName);
		goto errorinfo;
	}

	if (position == POSITIONUNASSIGNED) {
		debug.log(ALL_LEVEL, "selfIntegrityCheck: in %s not set \"position\" field, required", pluginName);
		goto errorinfo;
	}

	return true;

errorinfo:
	debug.log(DEBUG_LEVEL, "Documentation about plugins development: http://www.sniffjoke.net/delirandom/plugins");
	return false;
}

void Packet::IPHDR_resize(uint8_t size) 
{
	if (size == iphdrlen)
		return;
	
	const uint16_t pktlen = pbuf.size();
	
	/* 
	 * safety checks delegated to the function caller:
	 *   size : must be multiple of 4;
	 *   size : must be >= sizeof(struct iphdr));
	 *   size : must be <= MAXIPHEADER;
	 *   pktlen - iphdrlen + size : must be <= MTU.
	 */

	/* its important to update values into hdr before vector insert call because it can cause relocation */
	ip->ihl = size / 4;
	
	vector<unsigned char>::iterator it = pbuf.begin();

	if (iphdrlen < size) {
		ip->tot_len = htons(pktlen + (size - iphdrlen));
		pbuf.insert(it + iphdrlen, size - iphdrlen, IPOPT_NOOP);
	} else { /* iphdrlen > size */
		ip->tot_len = htons(pktlen - (iphdrlen - size));
		pbuf.erase(it + size, it + iphdrlen);
	}
	
	updatePacketMetadata();
}

void Packet::TCPHDR_resize(uint8_t size)
{
	if (size == tcphdrlen)
		return;
	
	const uint16_t pktlen = pbuf.size();

	/* 
	 * safety checks delegated to the function caller:
	 *   - size : must be multiple of 4;
	 *   - size : must be >= sizeof(struct tcphdr));
	 *   - size : must be <= MAXTCPHEADER;
	 *   - pktlen - tcphdrlen + size : must be <= MTU.
	 */
	
	/* its important to update values into hdr before vector insert call because it can cause relocation */
	tcp->doff = size / 4;
	
	vector<unsigned char>::iterator it = pbuf.begin() + iphdrlen;

	if (tcphdrlen < size) {
		ip->tot_len = htons(pktlen + (size - tcphdrlen));
		pbuf.insert(it + tcphdrlen, size - tcphdrlen, TCPOPT_NOP);
	} else { /* tcphdrlen > size */
		ip->tot_len = htons(pktlen - (tcphdrlen - size));
		pbuf.erase(it + size, it + tcphdrlen);
	}

	updatePacketMetadata();
}

void Packet::TCPPAYLOAD_resize(uint16_t size)
{
	if (size == datalen)
		return;
	
	const uint16_t pktlen = pbuf.size();
	
	/* begin safety checks */
	if (pktlen - datalen + size > MTU)
		SJ_RUNTIME_EXCEPTION("");
	/* end safety checks */

	const uint16_t new_total_len = pktlen - datalen + size;

	/* its important to update values into hdr before vector insert call because it can cause relocation */
	ip->tot_len = htons(new_total_len);

	pbuf.resize(new_total_len);
	
	updatePacketMetadata();
}

void Packet::TCPPAYLOAD_fillrandom()
{
	const uint16_t diff = pbuf.size() - (iphdrlen + tcphdrlen);
	memset_random(payload, diff);
}

bool Packet::Inject_IPOPT(bool corrupt, bool strip_previous)
{
	
	bool injected = false;
	
	const uint16_t pktlen = pbuf.size();

	uint8_t actual_iphdrlen = iphdrlen;

	uint8_t target_iphdrlen = MAXIPHEADER;

	snprintf(debug_buf, sizeof(debug_buf), "BEFORE strip [%d] iphdrlen %d tcphdrlen %d datalen %d pktlen %d", strip_previous, iphdrlen, tcphdrlen, datalen, (int)pbuf.size());
	selflog(__func__, debug_buf);

	if (strip_previous) {
		const uint16_t freespace = MTU - (pktlen - iphdrlen + sizeof(struct iphdr));

		if(freespace == 0)
			return false;

		actual_iphdrlen = sizeof(struct iphdr);
		target_iphdrlen = sizeof(struct iphdr) + (random() % (MAXIPHEADER - sizeof(struct iphdr)));

		if (freespace < target_iphdrlen)
			target_iphdrlen = freespace;
	} else if(iphdrlen <= (MAXIPHEADER - 4)) {
		const uint16_t freespace = MTU - pktlen;

		if(freespace == 0)
			return false;
		target_iphdrlen = iphdrlen + 3 + (random() % (MAXIPHEADER - iphdrlen - 3));

		if (freespace < target_iphdrlen)
			target_iphdrlen = freespace;
	} else {
		return false;
	}

	// iphdrlen must be a multiple of 4
	target_iphdrlen += (target_iphdrlen % 4) ? (4 - target_iphdrlen % 4) : 0;
	
	if (target_iphdrlen != iphdrlen)
		IPHDR_resize(target_iphdrlen);

	try {
		HDRoptions IPInjector(IPOPTS_INJECTOR, corrupt, (unsigned char *)ip + sizeof(struct iphdr), actual_iphdrlen, target_iphdrlen);
		uint8_t MAXITERATION = 5;

		do {
			injected |= IPInjector.randomInjector();

		} while (target_iphdrlen != actual_iphdrlen && MAXITERATION--);
	} catch(exception &e) {
		selflog(__func__, "ip injection is not possibile");
	}

	if (target_iphdrlen != actual_iphdrlen) {
		/* iphdrlen must be a multiple of 4, this last check is to permit IPInjector.randomInjector()
		   to inject options not aligned to 4 */
		actual_iphdrlen += (actual_iphdrlen % 4) ? (4 - actual_iphdrlen % 4) : 0;
		IPHDR_resize(actual_iphdrlen);
	}

	snprintf(debug_buf, sizeof(debug_buf), "AFTER strip [%d] iphdrlen %d tcphdrlen %d datalen %d pktlen %d", strip_previous, iphdrlen, tcphdrlen, datalen, (int)pbuf.size());
	selflog(__func__, debug_buf);
	
	return injected;
}


bool Packet::Inject_TCPOPT(bool corrupt, bool strip_previous)
{
	bool injected = false;

	const uint16_t pktlen = pbuf.size();
	
	uint8_t actual_tcphdrlen = tcphdrlen;
	
	uint8_t target_tcphdrlen = 0;

	snprintf(debug_buf, sizeof(debug_buf), "BEFORE strip [%d] iphdrlen %d tcphdrlen %d datalen %d pktlen %d", strip_previous, iphdrlen, tcphdrlen, datalen, (int)pbuf.size());
	selflog(__func__, debug_buf);
	
	if (strip_previous) {
		uint16_t freespace = MTU - (pktlen - tcphdrlen + sizeof(struct tcphdr));

		if(freespace == 0)
			return false;

		actual_tcphdrlen = sizeof(struct tcphdr);
		target_tcphdrlen = sizeof(struct tcphdr) + (random() % (MAXTCPHEADER - sizeof(struct tcphdr)));

		if (freespace < target_tcphdrlen)
			target_tcphdrlen = freespace;

	} else if(tcphdrlen <= (MAXTCPHEADER - 4)) {
		uint16_t freespace = MTU - pktlen;

		if(freespace == 0)
			return false;

		target_tcphdrlen = tcphdrlen + 3 + (random() % (MAXTCPHEADER - tcphdrlen - 3));

		if (freespace < target_tcphdrlen)
			target_tcphdrlen = freespace;
	} else {
		return false;
	}
	
	// tcphdrlen must be a multiple of 4
	target_tcphdrlen += (target_tcphdrlen % 4) ? (4 - target_tcphdrlen % 4) : 0;
	
	if (target_tcphdrlen != tcphdrlen)
		TCPHDR_resize(target_tcphdrlen);

	try {
		HDRoptions TCPInjector(TCPOPTS_INJECTOR, corrupt, (unsigned char *)tcp + sizeof(struct tcphdr), actual_tcphdrlen, target_tcphdrlen);
		uint8_t MAXITERATION = 5;

		do {
			injected |= TCPInjector.randomInjector();

		} while (target_tcphdrlen != actual_tcphdrlen && MAXITERATION--); 

	} catch(exception &e) {
		selflog(__func__, "tcp injection is not possibile");		
	}

	if (target_tcphdrlen != actual_tcphdrlen) {
		/* tcphdrlen must be a multiple of 4, this last check is to permit IPInjector.randomInjector()
		   to inject options not aligned to 4 */
		actual_tcphdrlen += (actual_tcphdrlen % 4) ? (4 - actual_tcphdrlen % 4) : 0;
		TCPHDR_resize(actual_tcphdrlen);
	}

	snprintf(debug_buf, sizeof(debug_buf), "AFTER strip [%d] iphdrlen %d tcphdrlen %d datalen %d pktlen %d", strip_previous, iphdrlen, tcphdrlen, datalen, (int)pbuf.size());
	selflog(__func__, debug_buf);
	
	return injected;
}

void Packet::selflog(const char *func, const char *loginfo) const
{
	if (debug.level() == SUPPRESS_LOG)
		return;
	
	const char *evilstr, *wtfstr, *sourcestr, *p;
	char protoinfo[MEDIUMBUF], saddr[MEDIUMBUF], daddr[MEDIUMBUF];

	p = inet_ntoa(*((struct in_addr *)&(ip->saddr)));
	strncpy(saddr, p, sizeof(saddr));

	p = inet_ntoa(*((struct in_addr *)&(ip->daddr)));
	strncpy(daddr, p, sizeof(daddr));

	switch(evilbit) {
		case GOOD: evilstr = "good"; break;
		case EVIL: evilstr = "evil"; break;
                default: case MORALITYUNASSIGNED: evilstr = "unassigned evilbit"; break;

	}

	switch(wtf) {
		case PRESCRIPTION: wtfstr ="prescripted"; break;
		case INNOCENT: wtfstr ="innocent"; break;
		case GUILTY: wtfstr ="badchecksum"; break;
		case MALFORMED: wtfstr ="malformed"; break;
                default: case JUDGEUNASSIGNED: wtfstr = "unassigned wtf"; break;
	}

	switch(source) {
		case TUNNEL: sourcestr = "tunnel"; break;
		case LOCAL: sourcestr = "local"; break;
		case NETWORK: sourcestr = "network"; break;
		case TTLBFORCE: sourcestr = "ttl force"; break;
		default: case SOURCEUNASSIGNED: sourcestr = "unassigned source"; break;
	}

	if(ipfragment) {
		debug.log(PACKETS_DEBUG, "%s : E|%s WTF|%s src %s|%s->%s ttl %d %s FRAGMENT",
			func, evilstr, wtfstr, sourcestr,
			saddr, daddr,
			ip->ttl, loginfo
		);
	} else {
		memset(protoinfo, 0x0, sizeof(protoinfo));
		switch(proto) {
			case TCP:
				snprintf(protoinfo, sizeof(protoinfo), "TCP sp %u dp %u SAFR{%d%d%d%d} len %d(%d) seq %x ack_seq %x",
					ntohs(tcp->source), ntohs(tcp->dest), tcp->syn, tcp->ack, tcp->fin, 
					tcp->rst, (int)pbuf.size(), (int)(pbuf.size() - iphdrlen - tcphdrlen), 
					ntohl(tcp->seq), ntohl(tcp->ack_seq)
				);
				break;
			case ICMP:
				snprintf(protoinfo, sizeof(protoinfo), "ICMP type %d code %d len %d(%d)",
					icmp->type, icmp->code,
					(int)pbuf.size(), (int)(pbuf.size() - iphdrlen - sizeof(struct icmphdr))
				);
				break;
			case OTHER_IP:
				snprintf(protoinfo, sizeof(protoinfo), "Other proto: %d", ip->protocol);
				break;
			case PROTOUNASSIGNED:
				snprintf(protoinfo, sizeof(protoinfo), "protocol unassigned! value %d", ip->protocol);
				break;
			default:
				debug.log(ALL_LEVEL, "Invalid and impossibile %s:%d %s", __FILE__, __LINE__, __func__);
				SJ_RUNTIME_EXCEPTION("");
				break;
		}
		
		debug.log(PACKETS_DEBUG, "%s : E|%s WTF|%s src %s|%s->%s proto [%s] ttl %d %s",
			func, evilstr, wtfstr, sourcestr,
			saddr, daddr,
			protoinfo, ip->ttl, loginfo
		);
	}

	memset((void*)debug_buf, 0x00, sizeof(debug_buf));
}
