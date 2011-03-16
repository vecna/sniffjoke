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

#ifndef SJ_TTLFOCUS_H
#define SJ_TTLFOCUS_H

#include "Utils.h"
#include "Packet.h"

/* IT'S FUNDAMENTAL TO HAVE ALL THIS ENUMS VALUES AS POWERS OF TWO TO PERMIT OR MASKS */

enum ttlsearch_t
{
    TTL_KNOWN = 1, TTL_BRUTEFORCE = 2, TTL_UNKNOWN = 4
};

struct option_discovery
{
    bool underTesting;
    bool confirmed;
    bool defaultWorking;
};

class TTLFocus
{
public:
    /* timing variables */
    time_t access_timestamp; /* access timestamp used to decretee expiry */
    time_t next_probe_time; /* timeout value used for ttlprobe schedule */
    time_t probe_timeout;

    /* status variables */
    ttlsearch_t status; /* status of the traceroute */
    uint8_t rand_key; /* random key used as try to discriminate traceroute packet */
    uint16_t puppet_port; /* random port used with the aim to not disturbe a session */

    uint8_t sent_probe; /* number of sent probes */
    uint8_t received_probe; /* number of received probes */

    /* ttl informations, results of the analysis */
    const uint32_t daddr; /* destination of the traceroute */
    uint8_t ttl_estimate; /* hop count estimate found during ttlbruteforce;
                             on status KNOWN   : represents the min working ttl found
                             on status UNKNOWN : represents the max expired ttl found */
    uint8_t ttl_synack; /* the value of the ttl read in the synack packet */

    /* per-dest tracking of which IP|TCP options will be effective or became dropped */
    struct option_discovery OptMap[SUPPORTED_OPTIONS];

    unsigned char probe_dummy[40]; /* dummy ttlprobe packet generated from the packet
                                      that scattered the ttlfocus creation.
                                      the packet size is always 40 bytes long,
                                      (sizeof(struct iphdr) + sizeof(struct tcphdr)) */

    TTLFocus(void);
    TTLFocus(const Packet &pkt);
    TTLFocus(const struct ttlfocus_cache_record &);
    ~TTLFocus(void);
    uint16_t selectPuppetPort(uint16_t);

    /* utilities */
    void selflog(const char *func, const char *format, ...) const;
};

class TTLFocusMap : public map<const uint32_t, TTLFocus*>
{
private:
    time_t manage_timeout;

    struct ttlfocus_timestamp_comparison
    {

        bool operator() (const TTLFocus *i, const TTLFocus * j)
        {
            return ( i->access_timestamp < j->access_timestamp);
        }

    } ttlfocusTimestampComparison;

public:
    TTLFocusMap(void);
    ~TTLFocusMap(void);
    TTLFocus& get(const Packet &);
    void manage(void);
    void load(void);
    void dump(void);
};

struct ttlfocus_cache_record
{
    time_t access_timestamp; /* access timestamp used to decretee expiry */
    uint32_t daddr; /* destination of the traceroute */
    uint8_t ttl_estimate; /* hop count estimate found during ttlbruteforce;
                             on status KNOWN   : represents the min working ttl found
                             on status UNKNOWN : represents the max expired ttl found */
    uint8_t ttl_synack; /* the value of the ttl read in the synack packet */

    unsigned char probe_dummy[40]; /* dummy ttlprobe packet generated from the packet
                                      that scattered the ttlfocus creation.
                                      the packet size is always 40 bytes long,
                                      (sizeof(struct iphdr) + sizeof(struct tcphdr)) */
};

#endif /* SJ_TTLFOCUS_H */
