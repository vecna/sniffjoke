/*'
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

#include "PluginPool.h"
#include "UserConf.h"

#include <dlfcn.h>

extern auto_ptr<UserConf> userconf;

PluginTrack::PluginTrack(const char *plugabspath, uint8_t enabledScrambles, const char *plugOpt)
{
    LOG_VERBOSE("constructor %s to %s options [%s]", __func__, plugabspath, plugOpt);

    char enabledScramblesStr[LARGEBUF] = {0};

    pluginHandler = dlopen(plugabspath, RTLD_NOW);
    if (pluginHandler == NULL)
        RUNTIME_EXCEPTION("unable to load plugin %s: %s", plugabspath, dlerror());

    /* http://www.opengroup.org/onlinepubs/009695399/functions/dlsym.html */

    /*
     * GCC/GXX -> warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
     *
     * THERE IS NO WAY TO AVOID IT!
     * for this reason our makefile is without -Werror
     */

    fp_CreatePluginObj = (constructor_f *) dlsym(pluginHandler, "createPluginObj");
    fp_DeletePluginObj = (destructor_f *) dlsym(pluginHandler, "deletePluginObj");
    fp_versionValue = (version_f *) dlsym(pluginHandler, "versionValue");

    if (fp_CreatePluginObj == NULL || fp_DeletePluginObj == NULL || fp_versionValue == NULL)
    {
        RUNTIME_EXCEPTION("plugin %s lack of packet mangling object", plugabspath);
    }

    if (strlen(fp_versionValue()) != strlen(SW_VERSION) || strcmp(fp_versionValue(), SW_VERSION))
    {
        RUNTIME_EXCEPTION("loading %s incorred version (%s) with SniffJoke %s",
                          plugabspath, fp_versionValue(), SW_VERSION);
    }

    selfObj = fp_CreatePluginObj();
    if (selfObj->pluginName == NULL)
    {
        RUNTIME_EXCEPTION("Invalid implementation: %s lack of ->PluginName member", plugabspath);
    }

    /* in future release some other information will be passed here. this function
     * is called only at plugin initialization and will be used for plugins setup */
    failInit = !selfObj->init(enabledScrambles, plugOpt);
    if (failInit)
        RUNTIME_EXCEPTION("Initialization failed!");

    snprintfScramblesList(enabledScramblesStr, sizeof (enabledScramblesStr), enabledScrambles);

    LOG_ALL("import of %s: %s + globally enabled Scramble %s: %s",
            plugabspath, selfObj->pluginName,
            enabledScramblesStr,
            failInit ? "fail" : "success"
            );
}

/*
 * the constructor of PluginPool is called once; in the TCPTrack constructor the class member
 * plugin_pool is instanced. what we need here is to read the entire plugin list, open and fix the
 * list, keeping track in listOfPlugin variable
 *
 *    plugin_pool()
 *
 * (class TCPTrack).plugin_pool is the name of the unique PluginPool element
 */
PluginPool::PluginPool(void) :
globalEnabledScrambles(0)
{
    /* globalEnabledScrambles is set from the sum of each plugin configuration */
    if (userconf->runcfg.onlyplugin[0])
        parseOnlyPlugin();
    else
        parseEnablerFile();

    if (!pool.size())
        RUNTIME_EXCEPTION("fatal error: loaded correctly 0 plugins");
    else
        LOG_ALL("loaded correctly %d plugins", pool.size());

    char enabledScramblesStr[LARGEBUF];
    snprintfScramblesList(enabledScramblesStr, sizeof (enabledScramblesStr), globalEnabledScrambles);
    LOG_ALL("Globally enabled scrambles: [%s]", enabledScramblesStr);
    LOG_ALL("SniffJoke will use this configuration to create confusion also on real packets");
}

PluginPool::~PluginPool(void)
{
    LOG_DEBUG("");

    /* call the distructor loaded from the plugins */
    for (vector<PluginTrack *>::iterator it = pool.begin(); it != pool.end(); ++it)
    {
        const PluginTrack *plugin = *it;

        LOG_DEBUG("calling %s destructor and closing plugin handler", plugin->selfObj->pluginName);

        plugin->fp_DeletePluginObj(plugin->selfObj);

        dlclose(plugin->pluginHandler);

        delete plugin;
    }
}

void PluginPool::importPlugin(const char *plugabspath, const char *enablerEntry, uint8_t enabledScramble, const char *pOpt)
{
    try
    {
        /* when onlyPlugin is true, is read as forceAlways, the frequence which happen to apply the plugin */
        PluginTrack *plugin = new PluginTrack(plugabspath, enabledScramble, pOpt);
        if (plugin->failInit)
        {
            LOG_DEBUG("failed initialization of %s: the used scramble are not enougth for the plugin requiremente", plugabspath);
            delete plugin;
        }
        else
        {
            pool.push_back(plugin);
            LOG_DEBUG("plugin %s implementation accepted", plugin->selfObj->pluginName);
        }
    }
    catch (runtime_error &e)
    {
        RUNTIME_EXCEPTION("unable to load plugin %s", enablerEntry);
    }

}

bool PluginPool::parseScrambleOpt(const char *list_str, uint8_t *retval, const char **opt)
{

    struct scrambleparm
    {
        const char *keyword;
        uint8_t scramble;
    };

#define SCRAMBLE_SUPPORTED    4
    const struct scrambleparm availablescramble[SCRAMBLE_SUPPORTED] = {
        { SCRAMBLE_TTL_STR, SCRAMBLE_TTL},
        { SCRAMBLE_MALFORMED_STR, SCRAMBLE_MALFORMED},
        { SCRAMBLE_CHECKSUM_STR, SCRAMBLE_CHECKSUM},
        { SCRAMBLE_INNOCENT_STR, SCRAMBLE_INNOCENT}
    };

    bool foundScramble = false;
    char copyStr[MEDIUMBUF] = {0}, *optParse = NULL;

    memcpy(copyStr, list_str, strlen(list_str));

    /* check if the option is used, the char used for separation is '+' 
     * optParse and copyStr are used for sanity check ONLY */
    if ((optParse = strchr(copyStr, '+')) != NULL)
    {
        (*optParse) = 0x00;
        (optParse)++;

        if (*optParse == 0x00)
        {
            LOG_ALL("no valid option passed after the control char '+': %s", list_str);
            goto invalid_parsing;
        }

        /* no other symbol are accepted */
        if (!isalnum(*optParse))
        {
            LOG_ALL("invalid char after '+' only alphanumeric and digit accepted: %s", list_str);
            goto invalid_parsing;
        }

        /* const assigment */
        (*opt) = strchr(list_str, '+');
        ++(*opt);
    }

    /*   the plugin_enable.conf.$LOCATION file has this format:
     *   plugin.so,SCRAMBLE1[,SCRAMBLE2][,SCRAMBLE3]         */
    for (uint32_t i = 0; i < SCRAMBLE_SUPPORTED; i++)
    {
        if (strstr(copyStr, availablescramble[i].keyword))
        {
            foundScramble = true;
            (*retval) |= availablescramble[i].scramble;
        }
    }

invalid_parsing:
    return foundScramble;
}

void PluginPool::parseOnlyPlugin(void)
{
    LOG_VERBOSE("onlyplugin [%s]", userconf->runcfg.onlyplugin);
    LOG_DEBUG("a single plugin is used and will be forced to be applied ALWAYS a session permits it");

    char *comma;
    const char *pluginOpt = NULL;
    char onlyplugin_cpy[MEDIUMBUF] = {0};
    char plugabspath[MEDIUMBUF] = {0};
    uint8_t pluginEnabledScrambles;

    snprintf(onlyplugin_cpy, sizeof (onlyplugin_cpy), userconf->runcfg.onlyplugin);

    if ((comma = strchr(onlyplugin_cpy, ',')) == NULL)
        RUNTIME_EXCEPTION("invalid use of --only-plugin: (%s)", userconf->runcfg.onlyplugin);

    *comma = 0x00;
    comma++;

    snprintf(plugabspath, sizeof (plugabspath), "%s%s.so", INSTALL_LIBDIR, onlyplugin_cpy);

    if (!parseScrambleOpt(comma, &pluginEnabledScrambles, &pluginOpt))
        RUNTIME_EXCEPTION("invalid use of --only-plugin: (%s)", userconf->runcfg.onlyplugin);

    importPlugin(plugabspath, userconf->runcfg.onlyplugin, pluginEnabledScrambles, pluginOpt);

    /* we keep track of enabled scramble to apply confusion on real good packets */
    globalEnabledScrambles |= pluginEnabledScrambles;
}

void PluginPool::parseEnablerFile(void)
{
    char enablerabspath[LARGEBUF] = {0};
    char plugabspath[MEDIUMBUF] = {0};
    char enabledScramblesStr[LARGEBUF] = {0};
    char enablerentry[LARGEBUF] = {0};

    snprintf(enablerabspath, sizeof (enablerabspath), "%s/%s", userconf->runcfg.working_dir, FILE_PLUGINSENABLER);

    FILE *plugfile = fopen(enablerabspath, "r");
    if (plugfile == NULL)
        RUNTIME_EXCEPTION("unable to open in reading %s: %s", enablerabspath, strerror(errno));

    uint8_t line = 0;
    do
    {
        char *comma;
        const char *pluginOpt = NULL;
        uint8_t enabledScrambles = 0;

        fgets(enablerentry, LARGEBUF, plugfile);
        ++line;

        if (enablerentry[0] == '#' || enablerentry[0] == '\n' || enablerentry[0] == ' ')
            continue;

        /* C's chop() */
        enablerentry[strlen(enablerentry) - 1] = 0x00;

        /* 11 is the minimum length of a ?.so plugin, comma and strlen("GUILTY") the shortest keyword */
        if (strlen(enablerentry) < 11 || feof(plugfile))
        {
            RUNTIME_EXCEPTION("reading %s: imported %d plugins, matched interruption at line %d",
                              FILE_PLUGINSENABLER, pool.size(), line);
        }

        /* parsing of the file line, finding the first comma and make it a 0x00 */
        if ((comma = strchr(enablerentry, ',')) == NULL)
        {
            RUNTIME_EXCEPTION("reading %s at line %d lack the comma separator for scramble selection",
                              FILE_PLUGINSENABLER, line);
        }

        /* name,SCRAMBLE became name[NULL]SCRAMBLE, *comma point to "S" */
        *comma = 0x00;
        comma++;

        snprintf(plugabspath, sizeof (plugabspath), "%s%s.so", INSTALL_LIBDIR, enablerentry);

        if (!parseScrambleOpt(const_cast<const char *> (comma), &enabledScrambles, &pluginOpt))
        {
            RUNTIME_EXCEPTION("in line %d (%s), no valid scramble are present in %s",
                              line, enablerentry, FILE_PLUGINSENABLER);
        }

        snprintfScramblesList(enabledScramblesStr, sizeof (enabledScramblesStr), enabledScrambles);

        LOG_VERBOSE("importing plugin [%s] enabled scrambles %s", enablerentry, enabledScramblesStr);
        importPlugin(plugabspath, enablerentry, enabledScrambles, pluginOpt);

        /* we keep track of enabled scramble to apply confusion on real good packets */
        globalEnabledScrambles |= enabledScrambles;

    }
    while (!feof(plugfile));

    fclose(plugfile);
}

uint8_t PluginPool::enabledScrambles()
{
    return globalEnabledScrambles;
}

