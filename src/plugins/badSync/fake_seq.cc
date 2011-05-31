/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010,2011 vecna <vecna@delirandom.net>
 *                           evilaliv3 <giovanni.pellerano@evilaliv3.org>
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
 * when a sniffer collect the file using the sequence as stream offset, injecting a
 * completely random seq should cause extremely large and empty flow, truncation or
 * apparently large missinsg block of data.
 * 
 * SOURCE: phrack, analysis of tcpflow, analysis of wireshark
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Plugin.h"

class fake_seq : public Plugin
{
#define PLUGIN_NAME "Fake SEQ"

public:

    fake_seq() :
    Plugin(PLUGIN_NAME, AGG_TIMEBASED5S)
    {
    };

    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        supportedScrambles = configuredScramble;
        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag == FINALHACK)
            return false;

        return (origpkt.fragment == false &&
                origpkt.proto == TCP &&
                !origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin &&
                origpkt.tcppayload != NULL);
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->randomizeID();

        /* under test the anticipation seq only */
        pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) + (random() % 5000) + 300);
        /* pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) - (random() % 5000)); */

        pkt->tcp->window = htons((random() % 80) * 64);
        pkt->tcp->ack = pkt->tcp->ack_seq = 0;

        uint16_t newpayloadlen = random() % 100 + 200;

        pkt->tcppayloadResize(newpayloadlen);
        pkt->tcppayloadRandomFill();

        pkt->source = PLUGIN;
        pkt->position = ANTICIPATION;
        pkt->wtf = pktRandomDamage(availableScrambles, supportedScrambles);
        pkt->choosableScramble = availableScrambles & supportedScrambles;

        upgradeChainFlag(pkt);

        pktVector.push_back(pkt);
    }
};

extern "C" Plugin* createPluginObj()
{
    return new fake_seq();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
