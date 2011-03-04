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

#ifndef SJ_HACKPOOL_H
#define SJ_HACKPOOL_H

#include "Utils.h"
#include "UserConf.h"
#include "Hack.h"

typedef Hack* constructor_f(bool);
typedef void destructor_f(Hack *);
typedef const char* version_f(void);

class PluginTrack
{
public:
    void *pluginHandler;

    constructor_f *fp_CreateHackObj;
    destructor_f *fp_DeleteHackObj;
    version_f *fp_versionValue;

    Hack* selfObj;
    bool failInit;

    PluginTrack(const char *, uint8_t, bool);
};

class HackPool : public vector<PluginTrack *>
{
private:
    const sj_config &runconfig;
    void importPlugin(const char *, const char *, uint8_t, bool);
    void parseEnablerFile(void);
    uint8_t parseScrambleList(const char *);
public:
    HackPool(const sj_config &);
    ~HackPool(void);
};

#endif /* SJ_HACKPOOL_H */
