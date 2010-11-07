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

#include "Packet.h"

class shift_ack : public HackPacket
{
#define HACK_NAME	"unexpected ACK shift"
public:
	virtual Packet *createHack(Packet &orig_packet)
	{
		orig_packet.selflog(HACK_NAME, "Original packet");
		Packet* ret = new Packet(orig_packet);

		ret->ip->id = htons(ntohs(ret->ip->id) + (random() % 10));
		ret->tcp->ack_seq = htonl(ntohl(ret->tcp->ack_seq) + 65535);

		ret->position = ANY_POSITION;
		ret->wtf = INNOCENT;

		ret->selflog(HACK_NAME, "Hacked packet");
		return ret;
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.tcp->ack != 0);
	}

	shift_ack(int plugin_index) {
		track_index = plugin_index;
		hackName = HACK_NAME;
		hack_frequency = COMPULSIVE;
	}

};

extern "C"  HackPacket* CreateHackObject(int plugin_tracking_index) {
	return new shift_ack(plugin_tracking_index);
}

extern "C" void DeleteHackObject(HackPacket *who) {
	delete who;
}

