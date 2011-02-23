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

#ifndef SJ_CONF_H
#define SJ_CONF_H

#include "Utils.h"
#include "IPList.h"
#include "SessionTrack.h"
#include "TTLFocus.h"
#include "internalProtocol.h"

#include <unistd.h>
#include <net/ethernet.h>

struct sj_cmdline_opts
{
    /* these date are not present in sj_config because the
     * effective configuration directory is generated as private 
     * data inside UserConf classes */
    char basedir[MEDIUMBUF];
    char location[MEDIUMBUF];

    /* START OF COMMON PART WITH sj_config */
    char user[MEDIUMBUF];
    char group[MEDIUMBUF];
    uint16_t debug_level;
    char admin_address[MEDIUMBUF];
    uint16_t admin_port;
    char onlyplugin[MEDIUMBUF];
    bool active;
    bool go_foreground;
    bool use_whitelist;
    bool use_blacklist;
    uint16_t max_ttl_probe;
    /* END OF COMMON PART WITH sj_config */

    bool force_restart;
};

/* those are the value used for track port strength of TCP coverage */
#define PORTNUMBER          65535

#define SCRAMBLE_TTL        1
#define SCRAMBLE_CHECKSUM   2
#define SCRAMBLE_MALFORMED  4
#define SCRAMBLE_INNOCENT   8

#define ISSET_TTL(byte)         (byte & SCRAMBLE_TTL)
#define ISSET_CHECKSUM(byte)    (byte & SCRAMBLE_CHECKSUM)
#define ISSET_MALFORMED(byte)   (byte & SCRAMBLE_MALFORMED)
#define ISSET_INNOCENT(byte)    (byte & SCRAMBLE_INNOCENT)

/* this is the struct keeping the sniffjoke variables, is loaded 
 * by the configuration file, when a command line option is specified 
 * the command line override the loaded data. the data here present will
 * be dumped overriding the previous config file
 */
struct sj_config
{
    float MAGIC; /* integrity check for saved binary configuration */
    char version[SMALLBUF]; /* SW_VERSION from hardcoded-defines.h */

    char working_dir[LARGEBUF];
    char location_name[MEDIUMBUF];

    /* START OF COMMON PART WITH sj_cmdline_opt */
    char user[MEDIUMBUF];
    char group[MEDIUMBUF];
    uint16_t debug_level;
    char admin_address[MEDIUMBUF];
    uint16_t admin_port;
    char onlyplugin[MEDIUMBUF];
    bool active;
    bool go_foreground;
    bool use_whitelist;
    bool use_blacklist;
    uint16_t max_ttl_probe;
    /* END OF COMMON PART WITH sj_cmdline_opt */

    /* mangling policies */
    uint16_t portconf[PORTNUMBER];
    IPListMap *whitelist;
    IPListMap *blacklist;

    /* system informations, autodetected */
    char local_ip_addr[SMALLBUF];
    char gw_ip_addr[SMALLBUF];
    char gw_mac_str[SMALLBUF];
    char gw_mac_addr[ETH_ALEN];
    char interface[SMALLBUF];
    uint8_t tun_number;

};

class UserConf
{
private:

    /* network configuration autodetect support functions */
    void autodetectLocalInterface(void);
    void autodetectLocalInterfaceIPAddress(void);
    void autodetectGWIPAddress(void);
    void autodetectGWMACAddress(void);
    void autodetectFirstAvailableTunnelInterface(void);
    void dropTrafficFromGateway(void);

    void parseOnlyParam(const char*);

    /* config file load/dump support*/
    void parseMatch(char *, const char *, FILE *, const char *, const char *);
    void parseMatch(uint16_t &, const char *, FILE *, uint16_t, const uint16_t);
    void parseMatch(bool &, const char *, FILE *, bool, const bool);
    bool parseLine(FILE *, char *, const char *);
    uint32_t dumpIfPresent(FILE *, const char *, char *);
    uint32_t dumpIfPresent(FILE *, const char *, uint16_t);
    uint32_t dumpIfPresent(FILE *, const char *, bool);

    /* import of the file containing the port range settings, and load the
     * default if not present, it use portLine class in portConfParsing.cc */
    void loadAggressivity(void);

    bool syncPortsFiles(void);
    bool syncIPListsFiles(void);

public:
    const struct sj_cmdline_opts &cmdline_opts;
    char configfile[LARGEBUF]; /* generated by runconfig.location + hardcoded-define */
    struct sj_config runconfig; /* the running configuration is accessible by other class */

    UserConf(const struct sj_cmdline_opts &);
    ~UserConf();

    /* call all the private method for setup networking -- in future need to be modify
     * for multi OS supports */
    void networkSetup(void);

    /* config file load/dump interface*/
    bool loadDiskConfiguration(void);
    bool syncDiskConfiguration(void);
};

#endif /* SJ_CONF_H */
