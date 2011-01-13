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
#include "SessionTrack.h"
#include "TTLFocus.h"
#include "internalProtocol.h"
#include <net/ethernet.h>

struct sj_cmdline_opts {
		char cfgfname[MEDIUMBUF];

		/* START OF COMMON PART WITH sj_config */
		char location[MEDIUMBUF];
		char enabler[MEDIUMBUF];
		char user[MEDIUMBUF];
		char group[MEDIUMBUF];
		char chroot_dir[MEDIUMBUF];
		char logfname[MEDIUMBUF];
		char logfname_packets[MEDIUMBUF];
		char logfname_sessions[MEDIUMBUF];
		uint16_t debug_level;
		char admin_address[MEDIUMBUF];
		uint16_t admin_port;
		char onlyplugin[MEDIUMBUF];
		bool active;
		uint16_t max_ttl_probe;
		char aggressivity_file[MEDIUMBUF];
		char frequency_file[MEDIUMBUF];
		/* END OF COMMON PART WITH sj_config */

		bool go_foreground;
		bool force_restart;

		char cmd_buffer[MEDIUMBUF];
};

/* those are the value used for track port strength of TCP coverage */
#define PORTNUMBER	65535
/* the value are defined in internalProtocol.h */

#define SCRAMBLE_TTL		1
#define SCRAMBLE_CHECKSUM	2
#define SCRAMBLE_MALFORMED	4
#define SCRAMBLE_INNOCENT	8

#define ISSET_TTL(byte)		(byte & SCRAMBLE_TTL)
#define ISSET_CHECKSUM(byte) 	(byte & SCRAMBLE_CHECKSUM)
#define ISSET_MALFORMED(byte) 	(byte & SCRAMBLE_MALFORMED)
#define ISSET_INNOCENT(byte)	(byte & SCRAMBLE_INNOCENT)

/* this is the struct keeping the sniffjoke variables, is loaded 
 * by the configuration file, when a command line option is specified 
 * the command line override the loaded data. the data here present will
 * be dumped overriding the previous config file
 */
struct sj_config {
		float MAGIC;				/* integrity check for saved binary configuration */
		char version[SMALLBUF];			/* SW_VERSION from hardcoded-defines.h */
		bool chrooted;				/* defauit: false = NOT CHROOTED */
	
		/* START OF COMMON PART WITH sj_cmdline_opt */
		char location[MEDIUMBUF];		/* default: "default" */ 
		char enabler[MEDIUMBUF];		/* default: from hardcoded-defines.h */
		char user[MEDIUMBUF];			/* default: idem */
		char group[MEDIUMBUF];			/* default: idem */
		char chroot_dir[MEDIUMBUF];		/* default: idem */
		char logfname[MEDIUMBUF];		/* default: idem */
		char logfname_packets[MEDIUMBUF];	/* default: idem */
		char logfname_sessions[MEDIUMBUF];	/* default: idem */
		uint16_t debug_level;			/* default: idem */
		char admin_address[MEDIUMBUF];		/* default: idem */
		uint16_t admin_port;			/* default: idem */
		char onlyplugin[MEDIUMBUF];		/* default: empty */
		bool active;				/* default: false = NOT ACTIVE */
		uint16_t max_ttl_probe;			/* default: idem */
		char aggressivity_file[MEDIUMBUF];	/* default: idem */
		char frequency_file[MEDIUMBUF];		/* default: idem */
		/* END OF COMMON PART WITH sj_cmdline_opt */

		/* those value are derived from sj_cmdline_opt but parsed in UserConf.cc */
		char ttlfocuscache_file[MEDIUMBUF];	/* constructed with TTLFOCUSCACHE_FILE + location */

		uint8_t portconf[PORTNUMBER];
	
		char local_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_mac_str[SMALLBUF];		/* default: autodetect */
		char gw_mac_addr[ETH_ALEN];		/* default: autodetect, the conversion of _str */
		char interface[SMALLBUF];		/* default: autodetect */
		uint8_t tun_number;			/* default: autodetect */
};

class UserConf {
private:
		uint8_t io_buf[HUGEBUF];			/* used to copy structs for command I/O */
		const char *resolve_weight_name(int);
		void compare_check_copy(char *target, uint32_t tlen, const char *sjdefault, const char *useropt);
		void autodetect_local_interface(void);
		void autodetect_local_interface_ip_address(void);
		void autodetect_gw_ip_address(void);
		void autodetect_gw_mac_address(void);
		void autodetect_first_available_tunnel_interface(void);
		void debug_cleanup();
		void onlyparam_parser(const char*);

		/* dumping configuration utilities */
		char configfile[LARGEBUF];
		bool load(const struct sj_cmdline_opts &);
		void dump(void);
public:
		bool &alive;
		bool chroot_status;
		struct sj_config runconfig;		/* the running configuration is accessible by other class */
		SessionTrackMap *sessiontrackmap;
		TTLFocusMap *ttlfocusmap;

		UserConf(const struct sj_cmdline_opts &, bool &alive);
		~UserConf();

		void network_setup(void);
		void attach_sessiontrackmap(SessionTrackMap *);
		void attach_ttlfocusmap(TTLFocusMap *);
		
		uint8_t* handle_cmd(const char *);
		void handle_cmd_start(void);
		void handle_cmd_stop(void);
		void handle_cmd_quit(void);
		void handle_cmd_dump(void);
		void handle_cmd_stat(void);
		void handle_cmd_info(void);
		void handle_cmd_showport(void);
		void handle_cmd_set(unsigned short, uint16_t, uint8_t);
		void handle_cmd_debuglevel(int);

		/* internalProtocol handling */
		void write_SJStatus(uint8_t);
		void write_SJPortStat(uint8_t);
		uint8_t *appendSJStatus(uint8_t *, int32_t, uint32_t, uint16_t);
		uint8_t *appendSJStatus(uint8_t *, int32_t, uint32_t, bool);
		uint8_t *appendSJStatus(uint8_t *, int32_t, uint32_t, char *);
		uint8_t *append_SJportBlock(uint8_t *, uint16_t, uint16_t, uint8_t);
		void write_SJProtoError(void);
		uint32_t dumpComment(uint8_t *, uint32_t, const char *);
		uint32_t dumpIfPresent(uint8_t *, uint32_t, const char *, char *);

		/* file loading support */
		void parseMatch(char *, const char *, FILE *, const char *, const char *);
		void parseMatch(uint16_t &, const char *, FILE *, uint16_t, const uint16_t);
		void parseMatch(bool &, const char *, FILE *, bool, const bool);
		bool parseLine(FILE *, char *, const char *);
		void fixLocation(char *, char *, const char *);

};

#endif /* SJ_CONF_H */
