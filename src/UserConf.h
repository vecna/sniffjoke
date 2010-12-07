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
#include <net/ethernet.h>

enum sj_proc_t { SJ_SERVER_PROC = 0, SJ_CLIENT_PROC = 1 };

struct sj_cmdline_opts {
		/* START OF COMMON PART WITH sj_config_opt */
		char cfgfname[MEDIUMBUF];
                char enabler[MEDIUMBUF];
		char user[MEDIUMBUF];
		char group[MEDIUMBUF];
		char chroot_dir[MEDIUMBUF];
		char logfname[LARGEBUF];
		char logfname_packets[LARGEBUF];
		char logfname_sessions[LARGEBUF];
		uint8_t debug_level;
		char admin_address[MEDIUMBUF];
		uint16_t admin_port;
		/* END OF COMMON PART WITH sj_config_opt */

		char onlyplugin[MEDIUMBUF];
		char scramble[4];   /* 3 options chars + \0 */
		bool go_foreground;
		bool force_restart;

		sj_proc_t process_type;
		char cmd_buffer[MEDIUMBUF];
};

/* the struct used for index the sniffjoke-client-commands */
struct command {
	const char *cmd;
	int related_args;
};


/* those are the value used for track port strength of TCP coverage */
#define PORTNUMBER  65535
enum Strength { NONE = 0, LIGHT = 1, NORMAL = 2, HEAVY = 3 };

/* --only parsing facilities */
#define YNcheck(byte) (byte != 'Y' && byte != 'N')

#define SCRAMBLE_TTL		1
#define SCRAMBLE_CHECKSUM	2
#define SCRAMBLE_MALFORMED	4

#define ISSET_TTL(byte)		(byte & SCRAMBLE_TTL)
#define ISSET_CHECKSUM(byte) 	(byte & SCRAMBLE_CHECKSUM)
#define ISSET_MALFORMED(byte) 	(byte & SCRAMBLE_MALFORMED)

struct sj_config {
		float MAGIC;				/* integrity check for saved binary configuration */
		char version[SMALLBUF];			/* SW_VERSION from hardcoded-defines.h */
		bool active;				/* default: false = NOT ACTIVE */
		bool chrooted;				/* defauit: false = NOT CHROOTED */
	
		/* START OF COMMON PART WITH sj_cmdline_opt */
		char cfgfname[MEDIUMBUF];		/* default: check hardcoded-defines.h */
		char enabler[MEDIUMBUF];		/* default: idem */
		char user[MEDIUMBUF];			/* default: idem */
		char group[MEDIUMBUF];			/* default: idem */
		char chroot_dir[MEDIUMBUF];		/* default: idem */
		char logfname[LARGEBUF];		/* default: idem */
		char logfname_packets[LARGEBUF];	/* default: idem */
		char logfname_sessions[LARGEBUF];	/* default: idem */
		uint8_t debug_level;			/* default: idem */
		char admin_address[MEDIUMBUF];		/* default: idem */
		uint16_t admin_port;			/* default: idem */
		/* END OF COMMON PART WITH sj_cmdline_opt */

		/* those value are derived from sj_cmdline_opt but parsed in UserConf.cc */
		char onlyplugin[MEDIUMBUF];		/* default: empty */
		uint8_t scrambletech;			/* default: idem */		
		char ttlfocuscache_file[MEDIUMBUF];	/* constructed with TTLFOCUSCACHE_FILE + gw_mac_str */

		uint8_t max_ttl_probe;			/* default: idem */
		Strength portconf[PORTNUMBER];
	
		char local_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_mac_str[SMALLBUF];		/* default: autodetect */
		char gw_mac_addr[ETH_ALEN];		/* default: autodetect, the conversion of _str */
		unsigned char interface[SMALLBUF];	/* default: autodetect */
		uint8_t tun_number;			/* default: autodetect */
};

class UserConf {
private:
		char io_buf[HUGEBUF];
		const char *resolve_weight_name(int);
		bool load(const char *);
		void dump(void);
		void compare_check_copy(char *target, uint32_t tlen, const char *sjdefault, const char *useropt);
		void autodetect_local_interface(void);
		void autodetect_local_interface_ip_address(void);
		void autodetect_gw_ip_address(void);
		void autodetect_gw_mac_address(void);
		void autodetect_first_available_tunnel_interface(void);
		void debug_cleanup();
		void onlyparam_parser(const char*);

public:
		bool &alive;
		bool chroot_status;
		struct sj_config runconfig;
		SessionTrackMap *sessiontrackmap;
		TTLFocusMap *ttlfocusmap;

		UserConf(const struct sj_cmdline_opts &, bool &alive);
		~UserConf();

		void network_setup(void);
		void attach_sessiontrackmap(SessionTrackMap *);
		void attach_ttlfocusmap(TTLFocusMap *);
		
		char* handle_cmd(const char *);
		void handle_cmd_start(void);
		void handle_cmd_stop(void);
		void handle_cmd_quit(void);
		void handle_cmd_saveconf(void);
		void handle_cmd_stat(void);
		void handle_cmd_info(void);
		void handle_cmd_showport(void);
		void handle_cmd_set(unsigned short, uint16_t, Strength);
		void handle_cmd_loglevel(int);
		bool parse_port_weight(char *, Strength *);
};

#endif /* SJ_CONF_H */
