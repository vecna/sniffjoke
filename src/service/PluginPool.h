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

#ifndef SJ_PLUGINPOOL_H
#define SJ_PLUGINPOOL_H

#include "Utils.h"
#include "UserConf.h"
#include "Plugin.h"

typedef Plugin* constructor_f();
typedef void destructor_f(Plugin *);
typedef const char* version_f(void);

class PluginTrack
{
public:
    void *pluginHandler;

    constructor_f *fp_CreatePluginObj;
    destructor_f *fp_DeletePluginObj;
    version_f *fp_versionValue;

    Plugin* selfObj;
    bool failInit;

    PluginTrack(const char *, uint8_t);
};

class PluginPool : public vector<PluginTrack *>
{
private:
    const sj_config &runconfig;
    void importPlugin(const char *, const char *, uint8_t);
    void parseEnablerFile(void);
    uint8_t parseScrambleList(const char *);

public:
    PluginPool(const sj_config &);
    ~PluginPool(void);
};

#endif /* SJ_PLUGINPOOL_H */
