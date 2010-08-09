#include "Packet.h"

#include <cstdlib>
#include <string.h>

Packet::Packet(int size, const unsigned char* buff, int buff_size) {
	pbuf = (unsigned char *)calloc(1, size);
	pbuf_size = size;
	orig_pktlen = buff_size;

	memcpy(pbuf, buff, buff_size);
	packet_id = make_pkt_id(buff);
	
	updatePointers();
}

Packet::Packet(const Packet* pkt) {
	pbuf = (unsigned char *)calloc(1, pkt->pbuf_size);
	pbuf_size = pkt->pbuf_size;
	orig_pktlen = pkt->orig_pktlen;

	proto = pkt->proto;
	source = pkt->source;
	status = pkt->status;
	wtf = pkt->wtf;

	memcpy(pbuf, pkt->pbuf, pkt->pbuf_size);
	packet_id = 0;
	
	updatePointers();
}

Packet::~Packet() {
	free(pbuf);
}

void Packet::resizePayload(int newlen) {
	int iphlen = ip->ihl * 4;
	int tcphlen = tcp->doff * 4;
	int oldlen = ntohs(ip->tot_len) - (iphlen + tcphlen);
	int newpbuf_size = pbuf_size - oldlen + newlen;
	unsigned char *newpbuf = (unsigned char *)calloc(1, newpbuf_size);
	int newtotallen = iphlen + tcphlen + newlen;
	
	/* IP header copy , TCP header copy, Payload copy, if preserved */
	memcpy(newpbuf, pbuf, newtotallen);
	free(pbuf);
	pbuf = newpbuf;
	updatePointers();
	
	/* fixing the new length */
	pbuf_size = newpbuf_size;
	orig_pktlen = ntohs(ip->tot_len);
	ip->tot_len = htons(newtotallen);
}

void Packet::updatePointers() {
	
	ip = (struct iphdr *)pbuf;
	if (ip->protocol == IPPROTO_TCP) {
		proto = TCP;
		tcp = (struct tcphdr *)((unsigned char *)(ip) + (ip->ihl * 4));
		icmp = NULL;
		payload = (unsigned char *)tcp + tcp->doff * 4;
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

unsigned int Packet::half_cksum(const void *pointed_data, int len)
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

unsigned short Packet::compute_sum(unsigned int sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short) ~sum;
}

void Packet::fixIpTcpSum()
{
	unsigned int sum;
	unsigned int l4len = ntohs(ip->tot_len) - (ip->ihl * 4);

	ip->check = 0;
	sum = half_cksum ((void *)ip, (ip->ihl * 4));
	ip->check = compute_sum(sum);
	tcp->check = 0;
	sum = half_cksum ((void *) &ip->saddr, 8);
	sum += htons (IPPROTO_TCP + l4len);
	sum += half_cksum ((void *)tcp, l4len);
	tcp->check = compute_sum(sum);
}

unsigned int Packet::make_pkt_id(const unsigned char* buf)
{
	struct iphdr *ip = (struct iphdr *)pbuf;
	struct tcphdr *tcp;

	if (ip->protocol == IPPROTO_TCP)
	{
		tcp = (struct tcphdr *)((unsigned char *)ip + (ip->ihl * 4));
		return tcp->seq;
	}
	else
		return 0; /* packet_id == 0 mean no ID check */
}
