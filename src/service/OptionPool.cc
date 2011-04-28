/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *
 * Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                          evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include "hardcodedDefines.h"

#include "OptionPool.h"

#include "UserConf.h"

extern auto_ptr<UserConf> userconf;
extern auto_ptr<OptionPool> opt_pool;

void OptionPool::select(uint8_t reqProto)
{
    settedProto = reqProto;
    counter = 0;
}

IPTCPopt* OptionPool::get(void)
{
    ++counter;

    if (counter == SUPPORTED_OPTIONS || loadedOptions[counter] == NULL)
        return NULL;

    if (loadedOptions[counter]->optProto == settedProto)
        return loadedOptions[counter];
    else
        return get();
}

IPTCPopt* OptionPool::getSingleOption(uint32_t sjOptIndex)
{
    if (sjOptIndex >= SUPPORTED_OPTIONS)
        RUNTIME_EXCEPTION("invalid use of optcode index");

    return (loadedOptions[sjOptIndex]);
}

corruption_t OptionPool::lineParser(FILE *flow, uint32_t optLooked)
{
    corruption_t retval = CORRUPTUNASSIGNED;
    char line[MEDIUMBUF];
    uint32_t linecnt = 0;

    do
    {
        uint32_t readedIndex, readedCorruption;

        fgets(line, MEDIUMBUF, flow);
        ++linecnt;

        if (feof(flow))
            break;

        if (strlen(line) < 2 || line[0] == '#')
            continue;

        sscanf(line, "%u,%u", &readedIndex, &readedCorruption);

        if (readedIndex < 1 || readedIndex > (SUPPORTED_OPTIONS - 1))
            RUNTIME_EXCEPTION("in option file invalid index at line %u", linecnt);

        if (readedIndex == optLooked)
            retval = (corruption_t) readedCorruption;
        else
            RUNTIME_EXCEPTION("found index %u instead of the expected %u (line %u)",
                              readedIndex, optLooked, linecnt);

    }
    while (retval == CORRUPTUNASSIGNED);

    if (retval == CORRUPTUNASSIGNED)
        RUNTIME_EXCEPTION("unable to found option index %u in the option config file", optLooked);

    LOG_VERBOSE("option index %d found value corruption value of %u", optLooked, (uint8_t) retval);

    return retval;
}

OptionPool::OptionPool()
{

    memset(loadedOptions, 0, sizeof (IPTCPopt*)*(SUPPORTED_OPTIONS));

    loadedOptions[SJ_IPOPT_NOOP] = new Io_NOOP(true);
    loadedOptions[SJ_IPOPT_TIMESTAMP] = new Io_TIMESTAMP(true);
    loadedOptions[SJ_IPOPT_TIMESTOVERFLOW] = new Io_TIMESTOVERFLOW(false);
    loadedOptions[SJ_IPOPT_LSRR] = new Io_LSRR(true);
    loadedOptions[SJ_IPOPT_RR] = new Io_RR(true);
    loadedOptions[SJ_IPOPT_RA] = new Io_RA(true);
    loadedOptions[SJ_IPOPT_CIPSO] = new Io_CIPSO(true);
    loadedOptions[SJ_IPOPT_SEC] = new Io_SEC(true);
    loadedOptions[SJ_IPOPT_SID] = new Io_SID(true);
    loadedOptions[SJ_TCPOPT_NOP] = new To_NOP(true);
    loadedOptions[SJ_TCPOPT_MD5SIG] = new To_MD5SIG(false);
    loadedOptions[SJ_TCPOPT_PAWSCORRUPT] = new To_PAWSCORRUPT(false);
    loadedOptions[SJ_TCPOPT_TIMESTAMP] = new To_TIMESTAMP(false);
    loadedOptions[SJ_TCPOPT_MSS] = new To_MSS(false);
    loadedOptions[SJ_TCPOPT_SACK] = new To_SACK(false);
    loadedOptions[SJ_TCPOPT_SACKPERM] = new To_SACKPERM(false);
    loadedOptions[SJ_TCPOPT_WINDOW] = new To_WINDOW(false);

    /* when is loaded the single plugin HDRoptions_probe, the option loader is instanced w/ NULL */
    if (!(userconf->runcfg.onlyplugin[0] != 0x00 && !memcmp(userconf->runcfg.onlyplugin, IPTCPOPT_TEST_PLUGIN, strlen(IPTCPOPT_TEST_PLUGIN))))
    {
        /* loading the configuration file, containings which option bring corruption for your ISP */
        /* NOW - sets with the default used by vecna & evilaliv3 */
        /* THESE DATA HAS TO BE LOADED FROM A Location-SPECIFIC CONFIGUATION FILE */
        corruption_t writUsage;
        FILE *optInput = fopen(FILE_IPTCPOPT_CONF, "r");

        if (optInput == NULL)
            RUNTIME_EXCEPTION("unable to open in reading options configuration %s: %s", FILE_IPTCPOPT_CONF, strerror(errno));

        for (uint8_t sjI = 1; sjI < SUPPORTED_OPTIONS; ++sjI)
        {
            writUsage = lineParser(optInput, sjI);
            loadedOptions[sjI]->optionConfigure(writUsage);
        }

        fclose(optInput);

        LOG_DEBUG("options configuration loaded correctly from %s: %d defs", FILE_IPTCPOPT_CONF, SUPPORTED_OPTIONS);
    }
    else
    {
        /* testing modality - all options are loaded without a corruption definitions */
        LOG_ALL("option configuration not supplied! Initializing in testing mode");
    }
}
