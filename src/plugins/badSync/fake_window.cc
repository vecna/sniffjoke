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
 * this hack alters the window value perceived by the sniffer for our source
 *
 * could be useful for futuer hacks.
 *
 *
 * SOURCE : deduction, whishful thinking
 * VERIFIED IN :
 * KNOW BUGS :
 * WRITTEN IN VERSION : 0.4.0
 */

#include "service/Plugin.h"

class fake_window : public Plugin
{
#define PLUGIN_NAME "Fake WINDOW"

public:

    fake_window() :
    Plugin(PLUGIN_NAME, AGG_ALWAYS)
    {
    };

    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        supportedScrambles = configuredScramble;
        return true;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag != HACKUNASSIGNED)
            return false;

        return (origpkt.fragment == false &&
                origpkt.proto == TCP &&
                !origpkt.tcp->syn &&
                !origpkt.tcp->rst &&
                !origpkt.tcp->fin);
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        Packet * const pkt = new Packet(origpkt);

        pkt->randomizeID();

        /* all to re - do */
        if (random_percent(50))
            pkt->tcp->window = 0; /* ZERO WINDOW */
        else
            memset_random(&(pkt->tcp->window), sizeof (pkt->tcp->window)); /* WINDOW UPDATE */

        /* a zero/update window could ack segments */
        if (random_percent(66))
        {
            pkt->tcp->ack = 1;
            memset_random(&(pkt->tcp->ack_seq), sizeof (pkt->tcp->ack_seq));
        }
        else
        {
            pkt->tcp->ack = 0;
            pkt->tcp->ack_seq = 0;
        }

        pkt->tcp->psh = 0;

        pkt->tcppayloadResize(0);

        pkt->source = PLUGIN;
        pkt->position = ANY_POSITION;
        pkt->wtf = pktRandomDamage(availableScrambles, supportedScrambles);
        pkt->choosableScramble = (availableScrambles & supportedScrambles);

        upgradeChainFlag(pkt);

        pktVector.push_back(pkt);
    }
};

extern "C" Plugin* createPluginObj()
{
    return new fake_window();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
