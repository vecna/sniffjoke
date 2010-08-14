#ifndef SJ_CONF_H
#define SJ_CONF_H

#include <net/ethernet.h>

#define MAGICVAL	0xADECADDE

#define HEAVY	0x04
#define NORMAL	0x03
#define LIGHT	0x02
#define NONE	0x01

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
		unsigned int debug_level;
		bool go_foreground;
		bool force_restart;
		FILE *logstream;
		FILE *packet_logstream;
		FILE *hacks_logstream;
};

struct sj_config {
		float MAGIC;							/* integrity check for saved binary configuration */
		bool sj_run;							/* default: false = NO RUNNING */
		const char *user;						/* default: nobody */
		const char *group;						/* default: nogroup */
		char chroot_dir[MEDIUMBUF];				/* default: /var/run/sniffjoke */
		char logfname[MEDIUMBUF];				/* default: /var/log/sniffjoke.log */
		int debug_level;						/* default: 1 */
		char local_ip_addr[SMALLBUF];			/* default: autodetect */
		char gw_ip_addr[SMALLBUF];				/* default: autodetect */
		char gw_mac_str[SMALLBUF];				/* default: autodetect */
		unsigned char gw_mac_addr[ETH_ALEN];	/* the conversion of _str */
		unsigned short max_ttl_probe;			/* default: 26 */
		unsigned char interface[SMALLBUF];		/* default: autodetect */
		int tun_number;							/* tunnel interface number */
		unsigned char portconf[PORTNUMBER];

		bool SjH__shift_ack;
		bool SjH__fake_data;
		bool SjH__fake_seq;
		bool SjH__fake_close;
		bool SjH__zero_window;
		bool SjH__valid_rst_fake_seq;
		bool SjH__fake_syn;
		bool SjH__half_fake_syn;
		bool SjH__half_fake_ack;
		bool SjH__inject_ipopt;
		bool SjH__inject_tcpopt;

		char *error;
};

class SjConf {
private:
		char io_buf[HUGEBUF];
		const char *resolve_weight_name(int);
public:
		struct sj_config *running;

		SjConf(struct sj_useropt *);
		~SjConf();

		void dump_config(const char *);

		char *handle_cmd_stat(void);
		char *handle_cmd_stop(void);
		char *handle_cmd_start(void);
		char *handle_cmd_set(unsigned short, unsigned short, unsigned char);
		char *handle_cmd_showport(void);
		char *handle_cmd_log(int);

};

#endif /* SJ_CONF_H */
