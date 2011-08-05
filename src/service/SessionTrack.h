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

#ifndef SJ_SESSIONTRACK_H
#define SJ_SESSIONTRACK_H

#include "Utils.h"
#include "Packet.h"

struct pkt_n_track {
    uint16_t natural;
    uint16_t injected;
    uint16_t dropped;
};

class SessionTrack
{
    friend class SessionTrackMap;

private:
    time_t access_timestamp; /* access timestamp used to decretee expiry */

public:

    uint8_t proto;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;

    struct pkt_n_track ingoing;
    struct pkt_n_track outgoing;

    SessionTrack(const Packet &);
    ~SessionTrack(void);

    /* utilities */
    void selflog(const char *func, const char *format, ...) const;
};

class SessionTrackKey
{
public:
    uint8_t proto;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;

    bool operator<(SessionTrackKey) const;

};

class SessionTrackMap : public map<const SessionTrackKey, SessionTrack*>
{
private:
    time_t manage_timeout;

    struct sessiontrack_timestamp_comparison
    {

        bool operator() (const SessionTrack *i, const SessionTrack * j)
        {
            return ( i->access_timestamp < j->access_timestamp);
        }

    } sessiontrackTimestampComparison;

public:
    SessionTrackMap(void);
    ~SessionTrackMap(void);

    SessionTrack& get(const Packet &);
    void manage(void);
};

#endif /* SJ_SESSIONTRACK_H */
