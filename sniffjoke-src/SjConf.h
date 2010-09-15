#ifndef SJ_CONF_H
#define SJ_CONF_H

#include "defines.h"

#include "SjUtils.h"
#include <net/ethernet.h>

#define HEAVY		0x04
#define NORMAL		0x03
#define LIGHT		0x02
#define NONE		0x01

#define PORTNUMBER  65535

struct port_range {
		unsigned short start;
		unsigned short end;
};

enum size_buf_t {
		SMALLBUF = 64,
		MEDIUMBUF = 256,
		LARGEBUF = 1024,
		HUGEBUF = 4096,
		GARGANTUABUF = 4096 * 4
};

struct sj_useropt {
		const char *cfgfname;
		const char *user;
		const char *group;
		const char *chroot_dir;
		const char *logfname;
		const char *requested_hacks;
		unsigned int debug_level;
		bool go_foreground;
		bool force_restart;
		FILE *logstream;
		FILE *packet_logstream;
		FILE *hacks_logstream;
};

struct sj_config {
		float MAGIC;				/* integrity check for saved binary configuration */
		bool sj_run;				/* default: false = NO RUNNING */
		char user[MEDIUMBUF];		/* default: check defines.h */
		char group[MEDIUMBUF];		/* default: check defines.h */
		char chroot_dir[MEDIUMBUF];		/* default: check defines.h */
		char logfname[MEDIUMBUF];		/* default: check defines.h */
		int debug_level;			/* default: check defines.h */
		char local_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_ip_addr[SMALLBUF];		/* default: autodetect */
		char gw_mac_str[SMALLBUF];		/* default: autodetect */
		unsigned char gw_mac_addr[ETH_ALEN];	/* the conversion of _str */
		unsigned short max_ttl_probe;		/* default: 30 */
		unsigned int max_sex_track;		/* default: 4096 */
		unsigned char interface[SMALLBUF];	/* default: autodetect */
		int tun_number;				/* tunnel interface number */
		unsigned int port_conf_set_n;		/* number of "set" usage */
		unsigned char portconf[PORTNUMBER];
		char fileconfname[MEDIUMBUF];

		/* hacks support */
		char hacks[CONFIGURABLE_HACKS_N];

		bool SjH__fake_data;
		bool SjH__fake_seq;
		bool SjH__fake_close;
		bool SjH__zero_window;
		bool SjH__valid_rst_fake_seq;
		bool SjH__fake_syn;
		bool SjH__shift_ack;
		bool SjH__half_fake_syn;
		bool SjH__half_fake_ack;
		bool SjH__fake_data_anticipation;
		bool SjH__fake_data_posticipation;

		bool SjH__inject_ipopt;
		bool SjH__inject_tcpopt;

		char *error;
};

class SjConf {
private:
		char io_buf[HUGEBUF];
		const char *resolve_weight_name(int);
		void compare_check_copy(char *, int, const char *, int , const char *);
		void autodetect_local_interface(void);
		void autodetect_local_interface_ip_address(void);
		void autodetect_gw_ip_address(void);
		void autodetect_gw_mac_address(void);
		void autodetect_first_available_tunnel_interface(void);

public:
		struct sj_config *running;

		SjConf(struct sj_useropt *);
		~SjConf();

		void dump(void);
		void setup_active_hacks(void);
		
		char *handle_cmd_stat(void);
		char *handle_cmd_stop(void);
		char *handle_cmd_start(void);
		char *handle_cmd_quit(void);
		char *handle_cmd_set(unsigned short, unsigned short, unsigned char);
		char *handle_cmd_showport(void);
		char *handle_cmd_log(int);
};

#endif /* SJ_CONF_H */
