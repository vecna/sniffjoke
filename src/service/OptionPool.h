/*
 * SniffJoke is a software able to confuse the Internet traffic analysis,
 * developed with the aim to improve digital privacy in communications and
 * to show and test some securiy weakness in traffic analysis software.
 *
 *  Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                           evilaliv3 <giovanni.pellerano@evilaliv3.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SJ_OPTIONPOOL_H
#define SJ_OPTIONPOOL_H

#include "IPTCPopt.h"
#include "IPTCPoptImpl.h"

class OptionPool
{
private:

    /* the settedProto and counter is used as static variable in the classes because is
     * used to track the counter in the getNextOpt methods */
    uint8_t settedProto;
    uint8_t counter;

    vector<IPTCPopt *> pool;
public:

    /* loadedOption is the main struct where the implementation are stored: HDRoptions
     * need to initialize every instance with them, and I've preferred a static reference */

    OptionPool();
    ~OptionPool();

    /* methods for popoulate <vector>availOpts in HDRoptions */
    IPTCPopt * get(uint32_t);

    /* construction is overloaded because in the UserConf routine the
     * configuration file is loaded and the static variable is setup.
     *
     * in hijacking time the constructor is called without any args */

    corruption_t lineParser(FILE *, uint32_t);
    const char *getCorruptionStr(corruption_t);

    void disableAllOptions(void);
};

#endif /* SJ_OPTIONPOOL_H */

