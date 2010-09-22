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
bool SjH__fake_syn::condition(const Packet &pkt)
{
	return true;
}

void SjH__fake_syn::hack()
{
	debug_info = (char *)"fake syn";
	resizePayload(0);
		
	ip->id = htons(ntohs(ip->id) + (random() % 10));
		
	tcp->psh = 0;
	tcp->syn = 1;
	tcp->seq = htonl(ntohl(tcp->seq) + 65535 + (random() % 5000));

	/* 20% is a SYN ACK */
	if ((random() % 5) == 0) { 
		tcp->ack = 1;
		tcp->ack_seq = random();
	} else {
		tcp->ack = tcp->ack_seq = 0;
	}

	/* payload is always truncated */
	ip->tot_len = htons((ip->ihl * 4) + (tcp->doff * 4));

	/* 20% had source and dest port reversed */
	if ((random() % 5) == 0) {
		unsigned short swap = tcp->source;
		tcp->source = tcp->dest;
		tcp->dest = swap;
	}
}
