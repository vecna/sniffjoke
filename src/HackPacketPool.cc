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

PluginTrack::PluginTrack(const char *plugabspath, unsigned int num) :
	pluginHandler(NULL),
	fp_CreateHackObj(NULL),
	fp_DeleteHackObj(NULL),
	selfObj(NULL),
	pluginPath(NULL),
	enabled(false)
{
	void *handler = dlopen(plugabspath, RTLD_NOW);
	if(handler == NULL) {
		internal_log(NULL, ALL_LEVEL, "fatal error: unable to load %s: %s", plugabspath, dlerror());
		return;
	}
	internal_log(NULL, DEBUG_LEVEL, "opened %s plugin", plugabspath);

	pluginHandler = handler;
	pluginPath = strdup(plugabspath);

	/* http://www.opengroup.org/onlinepubs/009695399/functions/dlsym.html */
	fp_CreateHackObj = (constructor_f *)dlsym(handler, "CreateHackObject");
	fp_DeleteHackObj = (destructor_f *)dlsym(handler, "DeleteHackObject");

	trackIndex = num;

}

PluginTrack::PluginTrack(const PluginTrack& cpy) {
	pluginHandler = cpy.pluginHandler;
	fp_CreateHackObj = cpy.fp_CreateHackObj;
	fp_DeleteHackObj = cpy.fp_DeleteHackObj;
	selfObj = cpy.selfObj;
	pluginPath = cpy.pluginPath;
	enabled = cpy.enabled;
	trackIndex = cpy.trackIndex;
}

/* Check if the constructor has make a good job - further checks need to be addedd */
bool PluginTrack::verifyPluginIntegrity(void)
{
	if(fp_CreateHackObj == NULL || fp_DeleteHackObj == NULL) {
		internal_log(NULL, DEBUG_LEVEL, "Hack plugin #%d lack of create/delete object", trackIndex);
		return false;
	}

	selfObj = fp_CreateHackObj(trackIndex);

	if(selfObj->hackName == NULL) {
		internal_log(NULL, DEBUG_LEVEL, "Hack plugin #%d lack of ->hackName member", trackIndex);
		return false;
	}

	if(selfObj->hack_frequency == 0) {
		internal_log(NULL, DEBUG_LEVEL, "Hack plugin #%d (%s) lack of ->hack_frequency", 
			trackIndex, selfObj->hackName);
		return false;
	}

	return true;
}

/*
 * the constructor of HackPacketPool is called once; in the TCPTrack constructor the class member
 * hack_pool is instanced. what we need here is to read the entire plugin list, open and fix the
 * list, keeping track in listOfHacks variable
 *
 *    hack_pool(sjconf->running)
 *
 * (class TCPTrack).hack_pool is the name of the unique HackPacketPool element
 */
HackPacketPool::HackPacketPool(char* enabler) :
	fail(false) 
{
	char plugabspath[MEDIUMBUF];
	FILE *plugfile;

	if((plugfile = fopen(enabler, "r")) == NULL) {
		internal_log(NULL, ALL_LEVEL, "unable to open in reading %s: %s", enabler, strerror(errno));
		fail = true;
		return;
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
			internal_log(NULL, VERBOSE_LEVEL, "reading %s: importend %d plugins, matched interruption at line %d",
				PLUGINSENABLER, size(), line);
			break;
		}

		snprintf(plugabspath, SMALLBUF * 2, "%s%s", INSTALL_LIBDIR, plugrelpath);

		void *handler = dlopen(plugabspath, RTLD_NOW);
		if(handler == NULL) {
			internal_log(NULL, ALL_LEVEL, "fatal error: unable to load %s: %s", plugabspath, dlerror());
			fail = true;
			break;
		}
		internal_log(NULL, DEBUG_LEVEL, "opened %s plugin", plugabspath);

		PluginTrack plugin(plugabspath, (unsigned int)size() + 1);
		if(!plugin.verifyPluginIntegrity()){	
			internal_log(NULL, ALL_LEVEL, "plugin %s incorret implementation: read the documentation!",
				basename(plugin.pluginPath) );
			fail = true;
			break;
		} else {
			push_back(plugin);
		}

		internal_log(NULL, DEBUG_LEVEL, "plugin %s implementation accepted", plugin.selfObj->hackName);

	} while(!feof(plugfile));

	if(fail || !size()) {
		internal_log(NULL, ALL_LEVEL, "loaded correctly %d plugins: FAILURE while loading detected", size());
		return;
	} else
		internal_log(NULL, ALL_LEVEL, "loaded correctly %d plugins", size());

	/* 
	 * TCPTrack.cc:86: warning: ISO C++ forbids casting between pointer-to-function and pointer-to-object
	 *
	 * THE IS NO WAY TO AVOID IT!
	 * need, for TCPTrack.cc to be compiled without -Werror 
	 */
}

HackPacketPool::~HackPacketPool() 
{
	/* call the distructor loaded from the plugins */
	vector<PluginTrack>::iterator it;
	PluginTrack *plugin;
	for ( it = begin(); it != end(); it++ ) 
	{
		plugin = &(*it);
		internal_log(NULL, VERBOSE_LEVEL, "calling %s destructor (%s)",	plugin->selfObj->hackName, plugin->pluginPath);

		plugin->fp_DeleteHackObj(plugin->selfObj);

		if(dlclose(plugin->pluginHandler)) 
			internal_log(NULL, ALL_LEVEL, "unable to close %s plugin: %s", plugin->pluginPath, dlerror());
		else
			internal_log(NULL, DEBUG_LEVEL, "closed handler of %s", plugin->pluginPath);

		free(plugin->pluginPath);
	}
}
