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
 * http://en.wikipedia.org/wiki/IPv4#Fragmentation
 * 
 * this hack is something like the fragmentation.cc;
 * the little difference is that it does not simply split a ip packet (or a fragment itself)
 * into two fragments but it also inject a fake fragment overlapped between the original ones.
 *
 * SOURCE: fragmentation historically is a pain in the ass for whom code firewall & sniffer
 * VERIFIED IN:
 * KNOW BUGS:
 */

#include "Hack.h"

class fragmentation_with_fake_data: public Hack
{
#define HACK_NAME	"Fragmentation With Fake Data"
public:
	virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
	{
		origpkt.selflog(HACK_NAME, "Original packet");

		if(!ISSET_TTL(availableScramble)) {
			debug.log(VERBOSE_LEVEL, "TTL/prescription hack not available in %s: loss hack possibility", HACK_NAME);
			return;
		}

		uint16_t ip_payload_len = ntohs(origpkt.ip->tot_len) - origpkt.iphdrlen;
		
		/* fragment's payload must be multiple of 8 (last fragment excluded of course) */
		uint16_t fraglen_first = ((uint16_t)((uint16_t)(ip_payload_len / 2) + (uint16_t)(ip_payload_len % 2)) >> 3) << 3;
		uint16_t fraglen_second = ip_payload_len - fraglen_first;
		
		vector<unsigned char> pbufcpy(origpkt.pbuf);
		vector<unsigned char>::iterator it = pbufcpy.begin();
		
		/* pkts's header initialization as origpkt's header copy */
		vector<unsigned char> pktbuf1(it, it + origpkt.iphdrlen);
		vector<unsigned char> pktbuf2(it, it + origpkt.iphdrlen);

		it += origpkt.iphdrlen;
		
		/* 
		 * pkts's:
		 *   - header fixation with correct fraglen and fragoffset
		 *   - payload fragmentation
		 */
		struct iphdr *ip1 = (struct iphdr *)&(pktbuf1[0]);
		ip1->tot_len = htons(origpkt.iphdrlen + fraglen_first);
		ip1->frag_off |= htons(IP_MF);	/* set more fragment bit */

		struct iphdr *ip2 = (struct iphdr *)&pktbuf2[0];
		ip2->tot_len = htons(origpkt.iphdrlen + fraglen_second);
		ip2->frag_off += htons(fraglen_first >> 3);

		pktbuf1.insert(pktbuf1.end(), it, it + fraglen_first);
		it += fraglen_first;
		pktbuf2.insert(pktbuf2.end(), it, it + fraglen_second);

		Packet* const frag1 = new Packet(&pktbuf1[0], pktbuf1.size());
		Packet* const frag2 = new Packet(&pktbuf2[0], pktbuf2.size());

		Packet* frag3_fake_overlapped = new Packet(*frag2);
		struct iphdr *ip3 = (struct iphdr *)&frag3_fake_overlapped->pbuf[0];
		if((fraglen_first >> 3) > 68) {
			uint16_t max_slide = (fraglen_first >> 3) - 68;
			ip3->frag_off = htons(ntohs(ip3->frag_off) - random() % max_slide);
		}
		
		frag1->ip->id = htons(ntohs(frag1->ip->id) - 10 + (random() % 20));
		frag2->ip->id = htons(ntohs(frag2->ip->id) - 10 + (random() % 20));
		frag3_fake_overlapped->ip->id = htons(ntohs(frag3_fake_overlapped->ip->id) - 10 + (random() % 20));
		
		memset_random((void*)((unsigned char *)ip3 + origpkt.iphdrlen), fraglen_second);
		
		frag1->wtf = INNOCENT;
		frag2->wtf = INNOCENT;
		frag3_fake_overlapped->wtf = PRESCRIPTION;
		frag3_fake_overlapped->choosableScramble = PRESCRIPTION;

		/*
		 * randomizing the relative between the three fragments;
		 * the orig packet is than removed.
		 */
		frag1->position = POSITIONUNASSIGNED;
		frag2->position = POSITIONUNASSIGNED;
		frag3_fake_overlapped->position = POSITIONUNASSIGNED;
		
		frag1->selflog(HACK_NAME, "Fragment 1");
		frag2->selflog(HACK_NAME, "Fragment 2");
		frag3_fake_overlapped->selflog(HACK_NAME, "Overlapped BAD fragment");

		pktVector.push_back(frag1);
		pktVector.push_back(frag2);
		pktVector.push_back(frag3_fake_overlapped);

		removeOrigPkt = true;
	}

	virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
	{
		/*
		 *  RFC 791 states:
		 * 
		 * "Every internet module must be able to forward a datagram of 68
		 *  octets without further fragmentation.  This is because an internet
		 *  header may be up to 60 octets, and the minimum fragment is 8 octets."
		 * 
		 */
		return 	(!(origpkt.ip->frag_off & htons(IP_DF))
			&& origpkt.iphdrlen + ((ntohs(origpkt.ip->tot_len) - origpkt.iphdrlen)/ 2) >= 68
			&& (availableScramble & PRESCRIPTION) );
	}

	virtual bool initializeHack(uint8_t configuredScramble) 
	{
		if ( ISSET_TTL(configuredScramble) && ISSET_INNOCENT(configuredScramble) ) {
			supportedScramble = configuredScramble;
			return true;
		} else {
			debug.log(ALL_LEVEL, "Fragmentation with fake data require INNOCENT and PRESCRIPTION as option");
			return false;
		}
	}

	fragmentation_with_fake_data() : Hack(HACK_NAME, ALWAYS) {}
};

extern "C"  Hack* CreateHackObject()
{
	return new fragmentation_with_fake_data();
}

extern "C" void DeleteHackObject(Hack *who)
{
	delete who;
}

extern "C" const char *versionValue()
{
 	return SW_VERSION;
}
