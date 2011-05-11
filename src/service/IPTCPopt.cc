/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *
 *  Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                           evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include "IPTCPopt.h"
#include "Utils.h"

IPTCPopt::IPTCPopt(bool enable, uint8_t sjI, const char * const sjN, uint8_t proto, uint8_t opcode) :
enabled(enable),
sjOptIndex(sjI),
sjOptName(sjN),
optProto(proto),
optValue(opcode),
availableUsage(CORRUPTUNASSIGNED)
{
}

void IPTCPopt::optionConfigure(corruption_t c)
{
    availableUsage = c;
}

/* this is the utility function used by the single option adder to calculate the best fit size for an option */
uint8_t IPTCPopt::getBestRandsize(struct optHdrData *oD, uint8_t fixedLen, uint8_t minRblks, uint8_t maxRblks, uint8_t blockSize)
{
    const uint8_t minComputed = fixedLen + (minRblks * blockSize);
    const uint8_t maxComputed = fixedLen + (maxRblks * blockSize);
    const uint8_t checkedAvail = oD->getAvailableOptLen();

    if (checkedAvail == minComputed || checkedAvail == maxComputed)
        return checkedAvail;

    if (checkedAvail < minComputed)
        return 0;

    if (checkedAvail > maxComputed)
        return (((random() % (maxRblks - minRblks + 1)) + minRblks) * blockSize) + fixedLen;

    /* else should try the best filling of memory and the NOP fill after */

    const uint8_t blockNumber = (checkedAvail - fixedLen) / blockSize;
    return ((blockNumber * blockSize) + fixedLen);
}

