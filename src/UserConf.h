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
		unsigned int debug_level;
		/* END OF COMMON PART WITH sj_config_opt */

		sj_proc_t process_type;
		char cmd_buffer[MEDIUMBUF];
		char onlyparm[MEDIUMBUF];
		bool go_foreground;
		bool force_restart;
		FILE *logstream;
		FILE *packet_logstream;
		FILE *session_logstream;
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
		unsigned int debug_level;		/* default: idem */
		/* END OF COMMON PART WITH sj_cmdline_opt */

		/* those value are derived from sj_cmdline_opt but parsed in UserConf.cc */
		char onlyplugin[MEDIUMBUF];		/* default: empty */
		unsigned char scrambletech;		/* default: idem */

		unsigned short max_ttl_probe;		/* default: idem */
		unsigned int max_sex_track;		/* default: idem */
		Strength portconf[PORTNUMBER];
	
		char local_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_mac_str[SMALLBUF];		/* default: autodetect */
		char gw_mac_addr[ETH_ALEN];		/* default: autodetect, the conversion of _str */
		unsigned char interface[SMALLBUF];	/* default: autodetect */
		int tun_number;				/* default: autodetect */
		unsigned int port_conf_set_n;		/* number of "set" usage */

		char *error;
};

class UserConf {
private:
		char io_buf[HUGEBUF];
		const char *resolve_weight_name(int);
		bool load(const char *);
		void dump(void);
		void compare_check_copy(char *, unsigned int, const char *, unsigned int , const char *);
		void autodetect_local_interface(void);
		void autodetect_local_interface_ip_address(void);
		void autodetect_gw_ip_address(void);
		void autodetect_gw_mac_address(void);
		void autodetect_first_available_tunnel_interface(void);
		void debug_cleanup();
		void onlyparm_parser(unsigned char &, char[MEDIUMBUF] , const char[MEDIUMBUF]);

public:
		bool chroot_status;
		struct sj_config running;

		UserConf(const struct sj_cmdline_opts &);
		~UserConf();

		void network_setup(void);
		
		char *handle_cmd_start(void);
		char *handle_cmd_stop(void);
		char *handle_cmd_quit(void);
		char *handle_cmd_saveconfig(void);
		char *handle_cmd_stat(void);
		char *handle_cmd_info(void);
		char *handle_cmd_showport(void);
		char *handle_cmd_set(unsigned short, unsigned short, Strength);
		char *handle_cmd_loglevel(int);
};

#endif /* SJ_CONF_H */
