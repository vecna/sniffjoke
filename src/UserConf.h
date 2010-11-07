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

#include "hardcoded-defines.h"
#include "Utils.h"

#include <net/ethernet.h>


enum size_buf_t {
		SMALLBUF = 64,
		MEDIUMBUF = 256,
		LARGEBUF = 1024,
		HUGEBUF = 4096,
		GARGANTUABUF = 4096 * 4
};

struct sj_useropt {
		char cfgfname[MEDIUMBUF];
                char enabler[MEDIUMBUF];
		char user[MEDIUMBUF];
		char group[MEDIUMBUF];
		char chroot_dir[MEDIUMBUF];
		char logfname[MEDIUMBUF];
		unsigned int debug_level;
		bool go_foreground;
		bool force_restart;
		FILE *logstream;
		FILE *packet_logstream;
		FILE *session_logstream;
};

/* those are the value used for track port strength of TCP coverage */
#define PORTNUMBER  65535
enum Strength { NONE = 0, LIGHT = 1, NORMAL = 2, HEAVY = 3 };

struct sj_config {
		float MAGIC;				/* integrity check for saved binary configuration */
		bool sj_run;				/* default: false = NO RUNNING */
		char cfgfname[MEDIUMBUF];
		char user[MEDIUMBUF];			/* default: check hardcoded-defines.h */
		char enabler[MEDIUMBUF];		/* default: idem */
		char group[MEDIUMBUF];			/* default: idem */
		char chroot_dir[MEDIUMBUF];		/* default: idem */
		char logfname[MEDIUMBUF];		/* default: idem */
		unsigned int debug_level;		/* default: idem */
		char local_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_mac_str[SMALLBUF];		/* default: autodetect */
		char gw_mac_addr[ETH_ALEN];		/* the conversion of _str */
		unsigned short max_ttl_probe;		/* default: 30 */
		unsigned int max_sex_track;		/* default: 4096 */
		unsigned char interface[SMALLBUF];	/* default: autodetect */
		int tun_number;				/* tunnel interface number */
		unsigned int port_conf_set_n;		/* number of "set" usage */

		Strength portconf[PORTNUMBER];

		char *error;
};

class UserConf {
private:
		char io_buf[HUGEBUF];
		const char *resolve_weight_name(int);
		void compare_check_copy(char *, unsigned int, const char *, unsigned int , const char *);
		void autodetect_local_interface(void);
		void autodetect_local_interface_ip_address(void);
		void autodetect_gw_ip_address(void);
		void autodetect_gw_mac_address(void);
		void autodetect_first_available_tunnel_interface(void);

public:
		struct sj_config running;

		UserConf(struct sj_useropt *);
		~UserConf();

		void dump(void);
		void setup_active_hacks(void);
		void network_setup(void);
		
		char *handle_cmd_stat(void);
		char *handle_cmd_stop(void);
		char *handle_cmd_start(void);
		char *handle_cmd_quit(void);
		char *handle_cmd_info(void);
		char *handle_cmd_set(unsigned short, unsigned short, Strength);
		char *handle_cmd_showport(void);
		char *handle_cmd_log(int);
		char *handle_cmd_status(void);
};

#endif /* SJ_CONF_H */
