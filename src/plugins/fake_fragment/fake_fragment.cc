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
 * the hacks inject two packet (maked as invalid, with TTL expiring or bad
 * checksum) with a fake segment, of the same length of the original packet,
 * one BEFORE and one AFTER the real packet. this cause that the sniffer (that 
 * eventually confirm the readed data when the data was acknowledged), had
 * memorized the first packet or the last only (because they share the same
 * sequence number). the reassembled flow appear override bye the data here
 * injected. should be the leverage for an applicative injection (like a 
 * fake mail instead of the real mail, etc...)
 * 
 * SOURCE: deduction, analysis of libnids
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Hack.h"

class fake_fragment : public Hack
{
#define HACK_NAME "Fake Fragment"

public:

    virtual void createHack(const Packet &origpkt, uint8_t availableScramble)
    {
        /*
         * in fake fragment I don't use pktRandomDamage because I want the
         * same hack for both packets.
         */
        judge_t selectedScramble;
        if (ISSET_TTL(availableScramble & supportedScramble) && RANDOMPERCENT(90))
            selectedScramble = PRESCRIPTION;
        else if (ISSET_MALFORMED(availableScramble & supportedScramble))
            selectedScramble = MALFORMED;
        else
            return;

        const uint32_t ip_payload = origpkt.pbuf.size() - origpkt.iphdrlen;

        uint8_t pkts = 2;
        while (pkts--)
        {
            Packet * const pkt = new Packet(origpkt);

            memset_random((void*) (((unsigned char *) &(pkt->pbuf[0])) + origpkt.iphdrlen), ip_payload);

            if (pkts == 2) /* first packet */
                pkt->position = ANTICIPATION;
            else /* second packet */
                pkt->position = POSTICIPATION;

            pkt->wtf = selectedScramble;
             pkt->choosableScramble = (availableScramble & supportedScramble);

            pktVector.push_back(pkt);
        }
    }

    virtual bool Condition(const Packet &origpkt, uint8_t availableScramble)
    {
        if (!(availableScramble & supportedScramble))
        {
            origpkt.SELFLOG("no scramble avalable for %s", HACK_NAME);
            return false;
        }
        return (origpkt.payload != NULL);
    }

    virtual bool initializeHack(uint8_t configuredScramble)
    {
        supportedScramble = configuredScramble;
        return true;
    }

    fake_fragment(bool forcedTest) : Hack(HACK_NAME, forcedTest ? AGG_ALWAYS : AGG_COMMON)
    {
    };
};

extern "C" Hack* CreateHackObject(bool forcedTest)
{
    return new fake_fragment(forcedTest);
}

extern "C" void DeleteHackObject(Hack *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
