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

#include "Hack.h"

class shift_ack : public Hack
{
#define HACK_NAME	"unexpected ACK shift"
public:
	virtual void createHack(const Packet &orig_packet)
	{
		orig_packet.selflog(HACK_NAME, "Original packet");

		Packet* pkt = new Packet(orig_packet);

		pkt->ip->id = htons(ntohs(pkt->ip->id) + (random() % 10));
		pkt->tcp->ack_seq = htonl(ntohl(pkt->tcp->ack_seq) + 65535);

		pkt->position = ANY_POSITION;
		pkt->wtf = INNOCENT;

		pkt->selflog(HACK_NAME, "Hacked packet");

		pktVector.push_back(pkt);
	}

	virtual bool Condition(const Packet &orig_packet)
	{
		return (orig_packet.tcp->ack != 0);
	}

	shift_ack() {
		hackName = HACK_NAME;
		hackFrequency = RARE;
	}

};

extern "C"  Hack* CreateHackObject() {
	return new shift_ack();
}

extern "C" void DeleteHackObject(Hack *who) {
	delete who;
}

extern "C" const char *versionValue() {
 	return SW_VERSION;
}
