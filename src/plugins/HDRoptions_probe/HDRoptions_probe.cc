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

#include "service/Plugin.h"
#include "service/HDRoptions.h"

class HDRoptions_probe : public Plugin
{
#define PLUGIN_NAME       "HDRoptions_probe"
#define LOGNAME_INNOCENT  "HDRoptions-MALFORMED.log"
#define LOGNAME_CORRUPT   "HDRoptions-INNOCENT.log"

#define MIN_TESTED_LEN  756

private:
    int32_t optIndex;
    pluginLogHandler *pLH;
    optionImplement *underTestOpt;
    bool testCorrupt;
    uint8_t supportedScramble;

    void applyTestedOption(Packet &target, bool corrupt)
    {
        TTLFocus dummy(target);

        if(underTestOpt->optProto == IPPROTO_IP)
        {
            HDRoptions IPInjector(IPOPTS_INJECTOR, target, dummy);
            IPInjector.injectSingleOpt(corrupt, true, underTestOpt->optValue);
        }
        else /* IPPROTO_TCP */
        {
            HDRoptions TCPInjector(TCPOPTS_INJECTOR, target, dummy);
            TCPInjector.injectSingleOpt(corrupt, true, underTestOpt->optValue);
        }
    }

public:
    HDRoptions_probe() :
    Plugin(PLUGIN_NAME, AGG_ALWAYS)
    {
        optIndex = -1;
        testCorrupt = false;
    }

    virtual bool init(uint8_t configuredScramble, const char *pluginOption)
    {
        bool retval = false;

        if(configuredScramble == INNOCENT)
        {
            pLH = new pluginLogHandler(PLUGIN_NAME, LOGNAME_INNOCENT);

            retval = true;
            testCorrupt = false;
        }

        if(configuredScramble == MALFORMED)
        {
            pLH = new pluginLogHandler(PLUGIN_NAME, LOGNAME_CORRUPT);

            retval = true;
            testCorrupt = true;
        }

        supportedScrambles = configuredScramble;

        if(retval) 
        {
            pLH->completeLog("initialized successfull HDRoption_probe: {%s} with string [%s][%d]", 
                            testCorrupt ? "CORRUPT" : "NOT CORRUPT", pluginOption, optIndex); 
        }

        if(pluginOption != NULL)
            optIndex = atoi(pluginOption);
        else
            retval = false;

        if(retval && optIndex >= 0 && optIndex < SUPPORTED_OPTIONS)
        {
            /* special usage: only in this testing modality will be used NULL as config file */
            optionLoader dummyConf(NULL);

            underTestOpt = dummyConf.getSingleOption(optIndex);

            pLH->completeLog("Option index [%d] point to %s (opcode %d)", 
                             optIndex, underTestOpt->sjOptName, underTestOpt->optValue);
        }
        else
        {
            retval = false;
            pLH->completeLog("invald option index used as argument: required >= 0 && < %d", 
                             SUPPORTED_OPTIONS);
        }

        return retval;
    }

    virtual bool condition(const Packet &origpkt, uint8_t availableScrambles)
    {
        if (origpkt.chainflag == FINALHACK)
            return false;

        return (origpkt.fragment == false && origpkt.proto == TCP && 
                /* our the is apply only in the sniffjoke-autotest packet containing the numbers */
                    origpkt.tcppayloadlen > MIN_TESTED_LEN);
    }

    virtual void apply(const Packet &origpkt, uint8_t availableScrambles)
    {
        Packet * pkt = new Packet(origpkt);

        pkt->randomizeID();

        pkt->source = PLUGIN;
        pkt->position = ANTICIPATION;

        if(supportedScramble == INNOCENT)
        {
            pkt->wtf = INNOCENT;

            applyTestedOption(*pkt, false);
            removeOrigPkt = true;
        }
        else
        {
            pkt->wtf = MALFORMED;

            applyTestedOption(*pkt, true);
        }

        upgradeChainFlag(pkt);
        pktVector.push_back(pkt);
    }
};

/* common and ripetitive code block */
extern "C" Plugin* createPluginObj()
{
    return new HDRoptions_probe();
}

extern "C" void deletePluginObj(Plugin *who)
{
    delete who;
}

extern "C" const char *versionValue()
{
    return SW_VERSION;
}
