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
#include "service/OptionPool.h"
#include "service/HDRoptions.h"

class HDRoptions_probe : public Plugin
{
#define PLUGIN_NAME       "HDRoptions_probe"
#define LOGNAME           "HDRoptions-testing.log"

#define MIN_TESTED_LEN  756

private:
    uint8_t sjOptIndex;
//    pluginLogHandler *pLH;
    IPTCPopt *underTestOpt;
    corruption_t CorruptionSet;

    void applyTestedOption(Packet &target)
    {
        TTLFocus dummy(target);

        if(underTestOpt->optProto == IPPROTO_IP)
        {
            HDRoptions IPInjector(IPOPTS_INJECTOR, target, dummy);
            /* true corrupt, true strip previous */
            IPInjector.injectSingleOpt(true, true, sjOptIndex );
        }
        else /* IPPROTO_TCP */
        {
            HDRoptions TCPInjector(TCPOPTS_INJECTOR, target, dummy);
            TCPInjector.injectSingleOpt(true, true, sjOptIndex );
        }
    }

public:
    HDRoptions_probe() :
    Plugin(PLUGIN_NAME, AGG_ALWAYS)
    {
        sjOptIndex = SUPPORTED_OPTIONS; /* the index really valid is SUPPORTED_OPTIONS -1
                                           so this way on error we will trigger an exception  */
    }

    /* init is called with pluginName,SCRAMBLE+option,
     * the option in this case is  */
    virtual bool init(uint8_t configuredScramble, char *pluginOption, struct sjEnviron *sjE)
    {
        OptionPool *optPool = reinterpret_cast<OptionPool *>(sjE->instanced_itopts);

//        pLH = new pluginLogHandler(PLUGIN_NAME, LOGNAME);

        if(pluginOption == NULL || strlen(pluginOption) == 1)
        {
            LOG_ALL("fatal: required $PLUGNAME,$SCRAMBLE+$OPTINDEX to be used: refer in the sniffjoke-iptcpoption script");
            return false;
        }

        CorruptionSet = CORRUPTUNASSIGNED;

        if(pluginOption[strlen(pluginOption) -1] == 'A')
            CorruptionSet = NOT_CORRUPT;
        if(pluginOption[strlen(pluginOption) -1] == 'B')
            CorruptionSet = ONESHOT;
        if(pluginOption[strlen(pluginOption) -1] == 'C')
            CorruptionSet = TWOSHOT;

        if(CorruptionSet == CORRUPTUNASSIGNED)
        {
            LOG_ALL("fatal: invalid usage of corruption selector - by hand usage is not suggested nor welcomed!");
            return false;
        }

        char *getIndex = strdup(pluginOption);
        getIndex[strlen(getIndex) -1] = 0x00;
        sjOptIndex = atoi(getIndex);
        free(getIndex);

        if(sjOptIndex < SUPPORTED_OPTIONS)
        {
            underTestOpt = optPool->get(sjOptIndex);

            /* we need to test ONESHOT and TWOSHOT, simply */
            underTestOpt->optionConfigure(CorruptionSet);

//            pLH->completeLog("Option index [%d] point to %s (opcode %d) and opt string [%s]", 
//                             sjOptIndex, underTestOpt->sjOptName, underTestOpt->optValue, pluginOption);

            if(!underTestOpt->enabled)
            {
                LOG_ALL("this options is not ENABLED!! error raised");
                return false;
            }

            LOG_ALL("Loading HDRoptions_probe (forced INNOCENT) with option [%s] index [%d] corruption %d",
                    pluginOption, sjOptIndex, CorruptionSet);
        }
        else
        {
            LOG_ALL("invald 'option index' passed as arg: required >= 0 && < %d", SUPPORTED_OPTIONS);
//            pLH->completeLog("invald 'option index' passed as arg: required >= 0 && < %d", SUPPORTED_OPTIONS);
            return false;
        }

        return true;
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

        /* the option will belive to corrupt the packet */
        applyTestedOption(*pkt);

        pkt->wtf = INNOCENT;
        pkt->choosableScramble = SCRAMBLE_INNOCENT;

        removeOrigPkt = true;

        LOG_PACKET("this packet with injected opt %s", underTestOpt->sjOptName);

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
