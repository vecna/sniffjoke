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

#include "HackPool.h"
#include "TCPTrack.h"

#include <dlfcn.h>

PluginTrack::PluginTrack(const char *plugabspath, uint8_t supportedScramble, bool pluginOnly)
{
    LOG_VERBOSE("%s", plugabspath);

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

    fp_CreateHackObj = (constructor_f *) dlsym(pluginHandler, "CreateHackObject");
    fp_DeleteHackObj = (destructor_f *) dlsym(pluginHandler, "DeleteHackObject");
    fp_versionValue = (version_f *) dlsym(pluginHandler, "versionValue");

    if (fp_CreateHackObj == NULL || fp_DeleteHackObj == NULL || fp_versionValue == NULL)
    {
        RUNTIME_EXCEPTION("hack plugin %s lack of packet mangling object", plugabspath);
    }

    if (strlen(fp_versionValue()) != strlen(SW_VERSION) || strcmp(fp_versionValue(), SW_VERSION))
    {
        RUNTIME_EXCEPTION("loading %s incorred version (%s) with SniffJoke %s",
                          plugabspath, fp_versionValue(), SW_VERSION);
    }

    if (pluginOnly)
        LOG_DEBUG("a single plugin is used and will be forced to be applied ALWAYS a session permits it");

    selfObj = fp_CreateHackObj(pluginOnly);

    if (selfObj->hackName == NULL)
    {
        RUNTIME_EXCEPTION("hack plugin %s lack of ->hackName member",
                          plugabspath);
    }

    /* in future release some other information will be passed here. this function
     * is called only at plugin initialization and will be used for plugins setup */
    failInit = !selfObj->initializeHack(supportedScramble);

    LOG_ALL("import of %s: %s with %s%s%s%s %s",
            plugabspath, selfObj->hackName,
            (ISSET_INNOCENT(supportedScramble) ? "INNOCENT," : ""),
            (ISSET_TTL(supportedScramble) ? "PRESCRIPTION," : ""),
            (ISSET_CHECKSUM(supportedScramble) ? "GUILTY," : ""),
            (ISSET_MALFORMED(supportedScramble) ? "MALFORMED" : ""),
            failInit ? "fail" : "success"
            );
}

/*
 * the constructor of HackPool is called once; in the TCPTrack constructor the class member
 * hack_pool is instanced. what we need here is to read the entire plugin list, open and fix the
 * list, keeping track in listOfHacks variable
 *
 *    hack_pool(sjconf->running)
 *
 * (class TCPTrack).hack_pool is the name of the unique HackPool element
 */
HackPool::HackPool(const sj_config &runcfg) :
runconfig(runcfg)
{
    LOG_VERBOSE("onlyplugin [%s]", runcfg.onlyplugin);

    if (runcfg.onlyplugin[0])
    {
        char *comma;
        char onlyplugin_cpy[MEDIUMBUF] = {0};
        char plugabspath[MEDIUMBUF] = {0};
        uint8_t supportedScramble;

        snprintf(onlyplugin_cpy, sizeof (onlyplugin_cpy), runcfg.onlyplugin);

        if ((comma = strchr(onlyplugin_cpy, ',')) == NULL)
            RUNTIME_EXCEPTION("invalid use of --only-plugin: (%s)", runcfg.onlyplugin);

        *comma = 0x00;
        comma++;

        snprintf(plugabspath, sizeof (plugabspath), "%s%s.so", INSTALL_LIBDIR, onlyplugin_cpy);

        if (!(supportedScramble = parseScrambleList(comma)))
            RUNTIME_EXCEPTION("invalid use of --only-plugin: (%s)", runcfg.onlyplugin);

        importPlugin(plugabspath, runcfg.onlyplugin, supportedScramble, true);
    }
    else
    {
        parseEnablerFile();
    }

    if (!size())
        RUNTIME_EXCEPTION("loaded correctly 0 plugins");
    else
        LOG_ALL("loaded correctly %d plugins", size());
}

HackPool::~HackPool()
{
    LOG_DEBUG("");

    /* call the distructor loaded from the plugins */
    for (vector<PluginTrack *>::iterator it = begin(); it != end(); ++it)
    {
        const PluginTrack *plugin = *it;

        LOG_DEBUG("calling %s destructor and closing plugin handler", plugin->selfObj->hackName);

        plugin->fp_DeleteHackObj(plugin->selfObj);

        dlclose(plugin->pluginHandler);

        delete plugin;
    }
}

void HackPool::importPlugin(const char *plugabspath, const char *enablerentry, uint8_t supportedScramble, bool onlyPlugin)
{
    try
    {
        /* when onlyPlugin is true, is read as forceAlways, the frequence which happen to apply the hacks */
        PluginTrack *plugin = new PluginTrack(plugabspath, supportedScramble, onlyPlugin);
        if (plugin->failInit)
        {
            LOG_DEBUG("failed initialization of %s: require scramble unsupported in the enabler file",
                      plugin->selfObj->hackName);
            delete plugin;
        }
        else
        {
            push_back(plugin);
            LOG_DEBUG("plugin %s implementation accepted", plugin->selfObj->hackName);
        }
    }
    catch (runtime_error &e)
    {
        RUNTIME_EXCEPTION("unable to load plugin %s", enablerentry);
    }

}

uint8_t HackPool::parseScrambleList(const char *list_str)
{

    struct scrambleparm
    {
        const char *keyword;
        uint8_t scramble;
    };
#define SCRAMBLE_SUPPORTED    4
    const struct scrambleparm availablescramble[SCRAMBLE_SUPPORTED] = {
        { "PRESCRIPTION", SCRAMBLE_TTL},
        { "MALFORMED", SCRAMBLE_MALFORMED},
        { "GUILTY", SCRAMBLE_CHECKSUM},
        { "INNOCENT", SCRAMBLE_INNOCENT}
    };

    int retval = 0;
    bool foundScramble = false;

    /*   the plugin_enable.conf.$LOCATION file has this format:
     *   plugin.so,SCRAMBLE1[,SCRAMBLE2][,SCRAMBLE3]         */
    for (uint32_t i = 0; i < SCRAMBLE_SUPPORTED; i++)
    {
        if (strstr(list_str, availablescramble[i].keyword))
        {
            foundScramble = true;
            retval |= availablescramble[i].scramble;
        }
    }

    if (!foundScramble)
    {
        LOG_ALL("in parser file, error@ [%s]", list_str);
        return 0;
    }

    return retval;
}

void HackPool::parseEnablerFile()
{
    char enablerabspath[LARGEBUF] = {0};
    char plugabspath[MEDIUMBUF] = {0};
    FILE *plugfile;

    snprintf(enablerabspath, sizeof (enablerabspath), "%s/%s", runconfig.working_dir, FILE_PLUGINSENABLER);

    if ((plugfile = fopen(enablerabspath, "r")) == NULL)
        RUNTIME_EXCEPTION("unable to open in reading %s: %s", enablerabspath, strerror(errno));

    uint8_t line = 0;
    do
    {
        char enablerentry[LARGEBUF], *comma;
        uint8_t supportedScramble = 0;

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
                              FILE_PLUGINSENABLER, size(), line);
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

        if (!(supportedScramble = parseScrambleList(comma)))
        {
            RUNTIME_EXCEPTION("in line %d (%s), no valid scramble are present in %s",
                              line, enablerentry, FILE_PLUGINSENABLER);
        }

        LOG_VERBOSE("Importing plugin [%s] supportedScramble %u", enablerentry, supportedScramble);
        importPlugin(plugabspath, enablerentry, supportedScramble, false);

    }
    while (!feof(plugfile));

    fclose(plugfile);
}
