/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011 vecna <vecna@delirandom.net>
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
 *   this research is dedicated to: http://www.youtube.com/watch?v=63FbXbJEmIs
 */

/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 *
 * This hack overlap one fake data sent before a real one, did the remote
 * kernel keep the first or the earliest ? seem that windows and unix have
 * different behaviour!
 * 
 * SOURCE: 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Hack.h"

class overlap_packet : public Hack
{
#define HACK_NAME "Overlap Packet"
#define PKT_LOG "overlapPacket.plugin.log"
#define MIN_PACKET_OVERTRY  300

private:
    pluginLogHandler pLH;

public:
	virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
	{
        /* the block split size must not create a last packet of 0 byte! */

        /* 
         * TODO -- 
         * with posticipation under Linux and Window the FIRST packet is accepted, and
         * the sniffer will keep the first or the last depends from the sniffing tech
         *
		pkt->position = POSTICIPATION; 
         *
         * Is explored here the usabilility of some TCPOPT making the packets unable
         * to be accepted (PAWS with expired timestamp) --- TODO
         */

        /* this test: a valid packet with a lenght LESS THAN the real size sent by
         * the kernel, followed by the same packet of good dimension. seem that
         * windows use the first received packet and unix the last received.
         */

        Packet* const pkt = new Packet(origpkt);
        pkt->tcppayloadResize(pkt->datalen - 100); 
        pLH.completeLog("original pkt size %d faked with %d bytes bad", origpkt.datalen, pkt->datalen);
        memset(pkt->payload, '6', pkt->datalen); 

        pkt->position = ANTICIPATION; 
        pkt->wtf = INNOCENT;
        pkt->tcp->psh = 0;
        pktVector.push_back(pkt);

        Packet* const pkt2 = new Packet(origpkt);
        pkt2->tcppayloadResize(pkt2->datalen); 
        // memset(pkt2->payload, '6', pkt2->datalen);
        pLH.completeLog("injected packet 2 with all byte good of %d/%d bytes", origpkt.datalen, pkt2->datalen);

        pkt2->position = POSTICIPATION; 
        pkt2->wtf = INNOCENT;
        pktVector.push_back(pkt2);

        removeOrigPkt = true;
	}

    /* the only acceptable Scramble is INNOCENT, because the hack is based on
     * overlap the fragment of the same packet */
	virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
	{
		if (origpkt.payload != NULL && origpkt.datalen > MIN_PACKET_OVERTRY)
            return true;

        return false;
	}

	virtual bool initializeHack(uint8_t configuredScramble)
	{
        if ( ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble) ) {
            LOG_ALL("%s hack supports only INNOCENT scramble type", HACK_NAME);
        }
		return true;
	}

	overlap_packet(bool forcedTest) : 
        Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_RARE ),
        pLH(HACK_NAME, PKT_LOG)
    {
    }
};

extern "C"  Hack* CreateHackObject(bool forcedTest)
{
	return new overlap_packet(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
	delete who;
}

extern "C" const char *versionValue()
{
 	return SW_VERSION;
}