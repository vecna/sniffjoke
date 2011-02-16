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
 */

/*
 * HACK COMMENT:, every hacks require intensive comments because should cause 
 * malfunction, or KILL THE INTERNET :)
 *
 * This hack overlap one fake data sent before a real one, did the remote
 * kernel keep the first or the earliest ? 
 * 
 * SOURCE: deduction, 
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Hack.h"

#define SCATTER_PKT_LOG     "overlapPacket.plugin.log"
/* is "try" because if the good packet is loss, all the session is it */
#define MIN_PACKET_OVERTRY  800

class overlap_packet : public Hack
{
private:
    pluginLogHandler *pLH;

#define HACK_NAME "Overlap Packet"
public:
	virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
	{
        /* the block split size must not create a last packet of 0 byte! */
        pLH->completeLog("packet size %d faking data with same lenght", origpkt.datalen);

		Packet* const pkt = new Packet(origpkt);
        /* with posticipation under Linux and Window the FIRST packet is accepted, and
         * the sniffer will keep the first or the last depends from the sniffing tech
         *
		pkt->position = POSTICIPATION; 
         *
         * Is explored here the usabilility of some TCPOPT
         */
        memset(pkt->payload, '6', pkt->datalen); 

        pkt->ip->id = 1;
		pkt->wtf = INNOCENT;
		pktVector.push_back(pkt);
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
        pLH = new pluginLogHandler( const_cast<const char *>(HACK_NAME), const_cast<const char *>(SCATTER_PKT_LOG));

        if ( ISSET_INNOCENT(configuredScramble) && !ISSET_INNOCENT(~configuredScramble) ) {
            LOG_ALL("%s hack supports only INNOCENT scramble type", HACK_NAME);
        }
		return true;
	}

	overlap_packet(bool forcedTest) : Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_RARE ) {};
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
