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
/* 
 * if the session is resetted, the remote box maybe vulnerable to:
 * Slipping in the window: TCP Reset attacks
 * http://kerneltrap.org/node/3072
 */
 SjH__valid_rst_fake_seq::SjH__valid_rst_fake_seq(const Packet pkt) : HackPacket(pkt) {
	debug_info = (char *)"valid rst fake seq";
	prejudge = INNOCENT;
	hack_frequency = 8;
}

void SjH__valid_rst_fake_seq::hack()
{
	resizePayload(0);

	ip->id = htons(ntohs(ip->id) + (random() % 10));
	tcp->seq = htonl(ntohl(tcp->seq) + 65535 + (random() % 12345));
	tcp->window = htons((unsigned short)(-1));
	tcp->rst = tcp->ack = 1;
	tcp->ack_seq = htonl(ntohl(tcp->seq) + 1);
	tcp->fin = tcp->psh = tcp->syn = 0;
}
