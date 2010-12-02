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

PluginTrack::PluginTrack(const char *plugabspath) :
	selfObj(NULL),
	pluginHandler(NULL),
	pluginPath(NULL),
	enabled(false),
	fp_CreateHackObj(NULL),
	fp_DeleteHackObj(NULL),
	fp_versionValue(NULL)
{
	debug.log(VERBOSE_LEVEL, __func__);	

	pluginHandler = dlopen(plugabspath, RTLD_NOW);
	if(pluginHandler == NULL) {
		debug.log(ALL_LEVEL, "PluginTrack: unable to load plugin %s: %s", plugabspath, dlerror());
		SJ_RUNTIME_EXCEPTION("");
	}

	debug.log(DEBUG_LEVEL, "PluginTrack: opened %s plugin", plugabspath);

	pluginPath = strdup(plugabspath);

        /* http://www.opengroup.org/onlinepubs/009695399/functions/dlsym.html */
        fp_CreateHackObj = (constructor_f *)dlsym(pluginHandler, "CreateHackObject");
        fp_DeleteHackObj = (destructor_f *)dlsym(pluginHandler, "DeleteHackObject");
	fp_versionValue = (version_f *)dlsym(pluginHandler, "versionValue");

        if(fp_CreateHackObj == NULL || fp_DeleteHackObj == NULL || fp_versionValue == NULL) {
                debug.log(ALL_LEVEL, "PluginTrack: hack plugin %s lack of create/delete object", pluginPath);
		SJ_RUNTIME_EXCEPTION("");
        }

	if(strlen(fp_versionValue()) != strlen(SW_VERSION) || strcmp(fp_versionValue(), SW_VERSION)) {
		debug.log(ALL_LEVEL, "PluginTrack: loading %s incorred version (%s) with SniffJoke %s",
			pluginPath, fp_versionValue(), SW_VERSION);
		SJ_RUNTIME_EXCEPTION("");
	}

        selfObj = fp_CreateHackObj();

        if(selfObj->hackName == NULL) {
                debug.log(ALL_LEVEL, "PluginTrack: hack plugin %s lack of ->hackName member", pluginPath);
		SJ_RUNTIME_EXCEPTION("");
        }

        if(selfObj->hackFrequency == FREQUENCYUNASSIGNED) {
                debug.log(ALL_LEVEL, "PluginTrack: hack plugin #%d (%s) lack of ->hack_frequency",
                        selfObj->hackName);
		SJ_RUNTIME_EXCEPTION("");
	}
}

PluginTrack::PluginTrack(const PluginTrack& cpy) {
	pluginHandler = cpy.pluginHandler;
	fp_CreateHackObj = cpy.fp_CreateHackObj;
	fp_DeleteHackObj = cpy.fp_DeleteHackObj;
	selfObj = cpy.selfObj;
	pluginPath = cpy.pluginPath;
	enabled = cpy.enabled;

	/* 
	 * GCC/GXX -> warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
	 *
	 * THE IS NO WAY TO AVOID IT!
	 * for this reason our makefile is without -Werror 
	 */
}

void HackPool::importPlugin(const char *plugabspath, const char *plugrelpath)
{
	try {
		PluginTrack plugin(plugabspath);
		push_back(plugin);
		debug.log(DEBUG_LEVEL, "HackPool: plugin %s implementation accepted", plugin.selfObj->hackName);
	} catch (runtime_error &e) {
		debug.log(ALL_LEVEL, "HackPool: unable to load plugin %s", plugrelpath);
		SJ_RUNTIME_EXCEPTION("");
	}

}

void HackPool::parseEnablerFile(const char *enabler)
{
	char plugabspath[MEDIUMBUF];
	FILE *plugfile;

	if((plugfile = fopen(enabler, "r")) == NULL) {
		debug.log(ALL_LEVEL, "HackPool: unable to open in reading %s: %s", enabler, strerror(errno));
		SJ_RUNTIME_EXCEPTION("");
	}

	uint8_t line = 0;
	do {
		char plugrelpath[SMALLBUF];

		fgets(plugrelpath, SMALLBUF, plugfile);
		line++;

		if(plugrelpath[0] == '#')
			continue;

		/* C's chop() */
		plugrelpath[strlen(plugrelpath) -1] = 0x00; 

		/* 4 is the minimum length of a ?.so plugin */
		if(strlen(plugrelpath) < 4 || feof(plugfile)) {
			debug.log(ALL_LEVEL, "HackPool: reading %s: importend %d plugins, matched interruption at line %d",
				PLUGINSENABLER, size(), line);
			SJ_RUNTIME_EXCEPTION("");
		}

		memset(plugabspath, 0x00, sizeof(plugabspath));
		snprintf(plugabspath, sizeof(plugabspath), "%s%s", INSTALL_LIBDIR, plugrelpath);
		importPlugin(plugabspath, plugrelpath);

	} while(!feof(plugfile));

	fclose(plugfile);
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
HackPool::HackPool(sj_config &runcfg)
{
	debug.log(VERBOSE_LEVEL, __func__);

	if(runcfg.onlyplugin[0])  {
		char plugabspath[MEDIUMBUF];
		memset(plugabspath, 0x00, sizeof(plugabspath));
		snprintf(plugabspath, sizeof(plugabspath), "%s%s", INSTALL_LIBDIR, runcfg.onlyplugin);
		importPlugin(plugabspath, runcfg.onlyplugin);
	} else {
		parseEnablerFile(const_cast<const char *>(runcfg.enabler));
	}

	if(!size()) {
		debug.log(ALL_LEVEL, "HackPool: loaded correctly 0 plugins: FAILURE while loading detected");
		SJ_RUNTIME_EXCEPTION("");
	} else
		debug.log(ALL_LEVEL, "HackPool: loaded correctly %d plugins", size());
}

HackPool::~HackPool() 
{
	debug.log(VERBOSE_LEVEL, __func__);

	/* call the distructor loaded from the plugins */
	for (vector<PluginTrack>::iterator it = begin(); it != end(); it++) 
	{
		PluginTrack *plugin = &(*it);

		debug.log(VERBOSE_LEVEL, "~HackPool: calling %s destructor (%s)",	plugin->selfObj->hackName, plugin->pluginPath);

		plugin->fp_DeleteHackObj(plugin->selfObj);

		if(dlclose(plugin->pluginHandler)) 
			debug.log(ALL_LEVEL, "~HackPool: unable to close %s plugin: %s", plugin->pluginPath, dlerror());
		else
			debug.log(VERBOSE_LEVEL, "~HackPool: closed handler of %s", plugin->pluginPath);

		free(plugin->pluginPath);
	}
}
