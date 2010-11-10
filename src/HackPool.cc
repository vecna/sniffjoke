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
#include "Utils.h"
#include "TCPTrack.h"

#include <dlfcn.h>

PluginTrack::PluginTrack(const char *plugabspath) :
	pluginHandler(NULL),
	fp_CreateHackObj(NULL),
	fp_DeleteHackObj(NULL),
	selfObj(NULL),
	pluginPath(NULL),
	enabled(false)
{
	pluginHandler = dlopen(plugabspath, RTLD_NOW);
	if(pluginHandler == NULL) {
		internal_log(NULL, ALL_LEVEL, "PluginTrack(): unable to load plugin %s: %s", plugabspath, dlerror());
		SJ_RUNTIME_EXCEPTION();
	}

	internal_log(NULL, DEBUG_LEVEL, "PluginTrack(): opened %s plugin", plugabspath);

	pluginPath = strdup(plugabspath);

        /* http://www.opengroup.org/onlinepubs/009695399/functions/dlsym.html */
        fp_CreateHackObj = (constructor_f *)dlsym(pluginHandler, "CreateHackObject");
        fp_DeleteHackObj = (destructor_f *)dlsym(pluginHandler, "DeleteHackObject");

        if(fp_CreateHackObj == NULL || fp_DeleteHackObj == NULL) {
                internal_log(NULL, DEBUG_LEVEL, "PluginTrack(): hack plugin %s lack of create/delete object", pluginPath);
		SJ_RUNTIME_EXCEPTION();
        }

        selfObj = fp_CreateHackObj();

        if(selfObj->hackName == NULL) {
                internal_log(NULL, DEBUG_LEVEL, "PluginTrack(): hack plugin %s lack of ->hackName member", pluginPath);
		SJ_RUNTIME_EXCEPTION();
        }

        if(selfObj->hackFrequency == FREQUENCYUNASSIGNED) {
                internal_log(NULL, DEBUG_LEVEL, "PluginTrack(): hack plugin #%d (%s) lack of ->hack_frequency",
                        selfObj->hackName);
		SJ_RUNTIME_EXCEPTION();
	}
}

PluginTrack::PluginTrack(const PluginTrack& cpy) {
	pluginHandler = cpy.pluginHandler;
	fp_CreateHackObj = cpy.fp_CreateHackObj;
	fp_DeleteHackObj = cpy.fp_DeleteHackObj;
	selfObj = cpy.selfObj;
	pluginPath = cpy.pluginPath;
	enabled = cpy.enabled;
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
HackPool::HackPool(char* enabler)
{
	char plugabspath[MEDIUMBUF];
	FILE *plugfile;

	if((plugfile = fopen(enabler, "r")) == NULL) {
		internal_log(NULL, ALL_LEVEL, "HackPool(): unable to open in reading %s: %s", enabler, strerror(errno));
		SJ_RUNTIME_EXCEPTION();
	}

	int line = 0;
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
			internal_log(NULL, VERBOSE_LEVEL, "HackPool(): reading %s: importend %d plugins, matched interruption at line %d",
				PLUGINSENABLER, size(), line);
			break;
		}

		snprintf(plugabspath, SMALLBUF * 2, "%s%s", INSTALL_LIBDIR, plugrelpath);

		try {
			PluginTrack plugin(plugabspath);
			push_back(plugin);
			internal_log(NULL, DEBUG_LEVEL, "HackPool(): plugin %s implementation accepted", plugin.selfObj->hackName);
		} catch (runtime_error &e) {
			internal_log(NULL, ALL_LEVEL, "HackPool(): unable to load plugin %s", plugrelpath);
		}

	} while(!feof(plugfile));

	fclose(plugfile);

	if(!size()) {
		internal_log(NULL, ALL_LEVEL, "HackPool(): loaded correctly 0 plugins: FAILURE while loading detected");
		SJ_RUNTIME_EXCEPTION();
	} else
		internal_log(NULL, ALL_LEVEL, "HackPool(): loaded correctly %d plugins", size());

	/* 
	 * TCPTrack.cc:86: warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
	 *
	 * THE IS NO WAY TO AVOID IT!
	 * need, for TCPTrack.cc to be compiled without -Werror 
	 */
}

HackPool::~HackPool() 
{
	/* call the distructor loaded from the plugins */
	vector<PluginTrack>::iterator it;
	PluginTrack *plugin;
	for ( it = begin(); it != end(); it++ ) 
	{
		plugin = &(*it);
		internal_log(NULL, VERBOSE_LEVEL, "~HackPool(): calling %s destructor (%s)",	plugin->selfObj->hackName, plugin->pluginPath);

		plugin->fp_DeleteHackObj(plugin->selfObj);

		if(dlclose(plugin->pluginHandler)) 
			internal_log(NULL, ALL_LEVEL, "~HackPool(): unable to close %s plugin: %s", plugin->pluginPath, dlerror());
		else
			internal_log(NULL, DEBUG_LEVEL, "~HackPool(): closed handler of %s", plugin->pluginPath);

		free(plugin->pluginPath);
	}
}
