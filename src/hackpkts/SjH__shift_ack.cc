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
#include "HackPacket.h"
/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 *
 * Some sniffer don't keep attenction to the sequence and the data, but to
 * the acknowledge sequence number. a shift sequence hack work sending a fake
 * ACK-packet with a seq_ack totally wrong. this was one of the hacks I've try
 * to use without GUILTY/PRESCRIPTION invalidation, but as INNOCENT, because 
 * if the ack is shifted more than the window value, the remote host must
 * invalidate them
 *
 * SOURCE: deduction, 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

SjH__shift_ack::SjH__shift_ack(const Packet pkt) :
	HackPacket(pkt, "shift ack")
{
	prejudge = INNOCENT;
	hack_frequency = 15;
}

bool SjH__shift_ack::condition(const Packet &pkt)
{
	return (pkt.tcp->ack != 0);
}

void SjH__shift_ack::hack()
{
	ip->id = htons(ntohs(ip->id) + (random() % 10));
	tcp->ack_seq = htonl(ntohl(tcp->ack_seq) + 65535);
}
