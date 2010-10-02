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
#include "sj_hackpkts.h"

SjH__fake_close::SjH__fake_close(const Packet pkt) :
	HackPacket(pkt, "fake close")
{
	prescription_probability = 98;
	hack_frequency = 5;
}

bool SjH__fake_close::condition(const Packet &pkt)
{
	return (pkt.tcp->ack != 0);
}

void SjH__fake_close::hack()
{
	const int original_size = orig_pktlen - (ip->ihl * 4) - (tcp->doff * 4);

	resizePayload(0);
		
	ip->id = htons(ntohs(ip->id) + (random() % 10));
		
	/* fake close could have FIN+ACK or RST+ACK */
	tcp->psh = 0;

	if (1) /* if (random() % 2) FIXME, a fake rst seems to break connection */
		tcp->fin = 1;
	else
		tcp->rst = 1;
	
	tcp->seq = htonl(ntohl(tcp->seq) - original_size + 1);
}
