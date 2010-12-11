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
 * fake close is used because a sniffer could read a FIN like a session closing
 * tcp-flag, and stop the session monitoring/reassembly.
 *
 * SOURCE: fragmentation historically is a pain in the ass for whom code firewall & sniffer
 * VERIFIED IN:
 * KNOW BUGS:
 */

#include "Hack.h"

class fragmentation: public Hack
{
#define HACK_NAME	"Fragmentation"
public:
	virtual void createHack(const Packet &origpkt)
	{
		origpkt.selflog(HACK_NAME, "Original packet");

		Packet* const frag1 = new Packet(origpkt);
		Packet* const frag2 = new Packet(origpkt);

		/* TODO: https://secure.wikimedia.org/wikipedia/en/wiki/IPv4#Fragmentation_and_reassembly */

		pktVector.push_back(frag1);
		pktVector.push_back(frag2);

		/* remove the original packet! only the two fragments will be shooted */
		/* p_queue.remove(&origpkt); */
		/* TODO: p_queue.remove will not be called from Hack, how will be solved ? 
		 * a boolean return value in createHack (delete or not original packet in TCPTrack.cc ?) */
	}

	virtual bool Condition(const Packet &origpkt)
	{
		return (origpkt.datalen > 512);
	}

	fragmentation() : Hack(HACK_NAME, PACKETS30PEEK) {}
};

extern "C"  Hack* CreateHackObject() {
	return new fragmentation();
}

extern "C" void DeleteHackObject(Hack *who) {
	delete who;
}

extern "C" const char *versionValue() {
 	return SW_VERSION;
}
