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
#include <cstdlib>
SjH__fake_seq::SjH__fake_seq(Packet& pkt) :
	HackPacket(pkt)
{
	debug_info = (char *)"fake seq";
	int diff = ntohs(ip->tot_len) - ((ip->ihl * 4) + (tcp->doff * 4));
	
	if(diff > 200) {
		diff = random() % 200;
		resizePayload(diff);
	}	
	
	int what = (random() % 3);

	ip->id = htons(ntohs(ip->id) + (random() % 10));

	if (what == 0)
		what = 2;

	if (what == 1) 
		tcp->seq = htonl(ntohl(tcp->seq) - (random() % 5000));

	if (what == 2)
		tcp->seq = htonl(ntohl(tcp->seq) + (random() % 5000));
			
	tcp->window = htons((random() % 80) * 64);
	tcp->ack = tcp->ack_seq = 0;

	fillRandomPayload();
}
