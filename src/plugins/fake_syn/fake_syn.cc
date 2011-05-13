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
 * a SYN packet, in a sniffer reassembly routine should mean the allocation/
 * opening of a new flow. if this syn packet collide with a previously 
 * allocated tuple, what happen ?
 * 
 * SOURCE: deduction
 * VERIFIED IN:
 * KNOW BUGS:
 * WRITTEN IN VERSION: 0.4.0
 */

#include "service/Plugin.h"

class fake_syn : public Plugin
{
#define PLUGIN_NAME "Fake SYN"

public:

    fake_syn() :
    Plugin(PLUGIN_NAME, AGG_RARE)
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
                origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin);
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        for (uint8_t pkts = 0; pkts < 2; pkts++)
        {
            Packet * const pkt = new Packet(origpkt);

            pkt->randomizeID();

            pkt->tcp->seq = htonl(ntohl(pkt->tcp->seq) + 65535 + (random() % 5000));

            /* 20% is a SYN ACK */
            if ((random() % 5) == 0)
            {
                pkt->tcp->ack = 1;
                pkt->tcp->ack_seq = random();
            }
            else
            {
                pkt->tcp->ack = 0;
                pkt->tcp->ack_seq = 0;
            }

            /* 20% had source and dest port reversed */
            if ((random() % 5) == 0)
            {
                uint16_t swap = pkt->tcp->source;
                pkt->tcp->source = pkt->tcp->dest;
                pkt->tcp->dest = swap;
            }

            pkt->source = PLUGIN;

            if (pkts == 0) /* first packet */
                pkt->position = ANTICIPATION;
            else /* second packet */
                pkt->position = POSTICIPATION;

            pkt->wtf = pktRandomDamage(availableScrambles, supportedScrambles);
            pkt->choosableScramble = (availableScrambles & supportedScrambles);

            upgradeChainFlag(pkt);

            pktVector.push_back(pkt);
        }
    }
};

extern "C" Plugin* createPluginObj()
{
    return new fake_syn();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
