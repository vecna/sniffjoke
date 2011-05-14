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

#ifndef SJ_IPTCPOPT_H
#define SJ_IPTCPOPT_H

#include "Utils.h"

/* NOT corrupt is an option that will never give an error, ONESHOT is an option that
 * make the packet dischargable, twoshot because some option trigger a fult if present
 * two time in the same header, and BOTH are option that will be either good or malformed
 * to be dumped by the remote host */
enum corruption_t
{
    CORRUPTUNASSIGNED = 0, NOT_CORRUPT = 1, ONESHOT = 2, TWOSHOT = 4, BOTH = 8, TRACK_ONLY = 16
};

struct optHdrData
{
    vector<uint8_t> optshdr;
    uint8_t actual_opts_len; /* max value 40 on IP and TCP too */

    uint8_t getAvailableOptLen()
    {
        /* using size had cause too much fault: now fuck tha vector */
        return 40 - /* (uint8_t)optshdr.size() - */ actual_opts_len;
    };
};

class IPTCPopt
{
public:
    bool enabled; /* static enabler */
    uint32_t sjOptIndex; /* sniffjoke options values */
    const char* const sjOptName;
    uint8_t optProto;
    uint8_t optValue; /* rfc options values*/
    corruption_t availableUsage;

    uint8_t getBestRandsize(struct optHdrData *, uint8_t, uint8_t, uint8_t, uint8_t);

    IPTCPopt(bool, uint8_t, const char *, uint8_t, uint8_t);

    void optionConfigure(corruption_t);
    virtual uint8_t optApply(struct optHdrData *) = 0;
};

#endif /* SJ_IPTCPOPT_H */

