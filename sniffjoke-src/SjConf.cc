#include <iostream>
#include <cerrno>
using namespace std;

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "SjUtils.h"
#include "SjConf.h"

SjConf::SjConf(struct sj_useropt *user_opt) 
{
	float magic_check = (MAGICVAL * 28.26);
	FILE *cF;
	int i;
	
	FILE *foca;
	char imp_str[SMALLBUF];

	const char *cmd0 = "ifconfig -a | grep tun | cut -b -7";
	const char *cmd1 = "grep 0003 /proc/net/route | grep 00000000 | cut -b -7";
	char cmd2[MEDIUMBUF];
	const char *cmd3 = "route -n | grep ^0.0.0.0 | grep UG | cut -b 17-32"; 
	char cmd4[MEDIUMBUF];

	running = (struct sj_config *)malloc(sizeof(struct sj_config));

	internal_log(NULL, DEBUG_LEVEL, "opening configuration file: %s", user_opt->cfgfname);
	if(user_opt != NULL && ((cF = fopen(user_opt->cfgfname, "r")) != NULL)) 
	{
		struct sj_config readed;

		memset(&readed, 0x00, sizeof(struct sj_config));

		i = fread((void *)&readed, sizeof(struct sj_config), 1, cF);
		check_call_ret("fread of config file", errno, (i - 1), false);
		internal_log(NULL, DEBUG_LEVEL, "reading of %s: %d byte readed", user_opt->cfgfname, i * sizeof(struct sj_config));

		if(readed.MAGIC != magic_check) {
			internal_log(NULL, ALL_LEVEL, "magic number of sniffjoke cfg: %s file seem to be corrupted -- delete them", 
				user_opt->cfgfname
			);
			check_call_ret("invalid checksum of config file", EINVAL, -1, true);
		}

		internal_log(NULL, VERBOSE_LEVEL, "readed configuration settings in %s", user_opt->cfgfname);
		internal_log(NULL, VERBOSE_LEVEL, "-- sniffjoke running: %s", readed.sj_run == true ? "TRUE" : "FALSE");
		internal_log(NULL, VERBOSE_LEVEL, "-- sniffjoke gateway mac address: %s", readed.gw_mac_str);
		internal_log(NULL, VERBOSE_LEVEL, "-- sniffjoke gateway ip address: %s", readed.gw_ip_addr);
		internal_log(NULL, VERBOSE_LEVEL, "-- sniffjoke local interface: %s, %s address", readed.interface, readed.local_ip_addr);
		internal_log(NULL, VERBOSE_LEVEL, "-- sniffjoke dynamic tunnel interface: tun%d", readed.tun_number);

		fclose(cF);

		memcpy(running, &readed, sizeof(struct sj_config));
		
	} else {

		memset(running, 0x00, sizeof(sj_config));

		/* begin autodetecting interface */
		internal_log(NULL, ALL_LEVEL, "++ detecting external gateway interface with [%s]", cmd1);
		foca = popen(cmd1, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && isalnum(imp_str[i]); i++)
			running->interface[i] = imp_str[i];

		if(i < 3) {
			internal_log(NULL, ALL_LEVEL, "-- default gateway not present: sniffjoke cannot be started");
			raise(SIGTERM);
		} else {
			internal_log(NULL, ALL_LEVEL, "  == detected external interface with default gateway: %s", running->interface);
		}
		/* end autodetect interface */
			
		/* begin autodect interface local ip address */
		snprintf(cmd2, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21-", 
		running->interface
		);
		internal_log(NULL, ALL_LEVEL, "++ detecting interface %s ip address with [%s]", running->interface, cmd2);
		foca = popen(cmd2, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isdigit(imp_str[i]) || imp_str[i] == '.' ); i++)
			running->local_ip_addr[i] = imp_str[i];

		internal_log(NULL, ALL_LEVEL, "  == acquired local ip address: %s", running->local_ip_addr);
		/* end autodetect interface local ip address */

		/* begin autodetect gw ip addr */
		internal_log(NULL, ALL_LEVEL, "++ detecting gateway ip address with [%s]", cmd3);
		foca = popen(cmd3, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isdigit(imp_str[i]) || imp_str[i] == '.' ); i++) 
			running->gw_ip_addr[i] = imp_str[i];

		if(strlen(running->gw_ip_addr) < 7) {
			internal_log(NULL, ALL_LEVEL, "  -- unable to autodetect gateway ip address, sniffjoke cannot be started");
			raise(SIGTERM);
		} else  {
			internal_log(stdout, ALL_LEVEL, "  == acquired gateway ip address: %s", running->gw_ip_addr);
		}
		/* end autodetect gw ip addr */

		/* begin autodetect gw mac address */
		snprintf(cmd4, MEDIUMBUF, "ping -W 1 -c 1 %s", running->gw_ip_addr);
		internal_log(NULL, ALL_LEVEL, "++ pinging %s for ARP table popoulation motivations [%s]", running->gw_ip_addr, cmd4);
		system(cmd4);
		usleep(50000);
		memset(cmd4, 0x00, MEDIUMBUF);
		snprintf(cmd4, MEDIUMBUF, "arp -n | grep %s | cut -b 34-50", running->gw_ip_addr);
		internal_log(NULL, ALL_LEVEL, "++ detecting mac address of gateway with %s", cmd4);
		foca = popen(cmd4, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isxdigit(imp_str[i]) || imp_str[i] == ':' ); i++)
			running->gw_mac_str[i] = imp_str[i];
		if(i != 17) {
			internal_log(NULL, ALL_LEVEL, "  -- unable to autodetect gateway mac address");
			raise(SIGTERM);
		} else {
			internal_log(NULL, ALL_LEVEL, "  == automatically acquired mac address: %s", running->gw_mac_str);
			sscanf( running->gw_mac_str, "%hX:%hX:%hX:%hX:%hX:%hX",
				&running->gw_mac_addr[0], &running->gw_mac_addr[1], 
				&running->gw_mac_addr[2], &running->gw_mac_addr[3], 
				&running->gw_mac_addr[4], &running->gw_mac_addr[5]
			);
		}
		/* end autodect gw mac address */
		
		/* autodetecting first tunnel device free */
		internal_log(NULL, ALL_LEVEL, "++ detecting first unused tunnel device with [%s]", cmd0);
		foca = popen(cmd0, "r");
		for(running->tun_number = 0; ; running->tun_number++)
		{
			memset(imp_str, 0x00, SMALLBUF);
			fgets(imp_str, SMALLBUF, foca);
			if(imp_str[0] == 0x00)
				break;
		}
		pclose(foca);
		internal_log(NULL, ALL_LEVEL, "  == detected %d as first unused tunnel device", running->tun_number);
		/* end autodetect first tunnel device free */

		/* set up defaults */		
		running->MAGIC = magic_check;
		running->sj_run = false;
		running->debug_level = 1;
		running->max_ttl_probe = 26;
		running->max_session_tracked = 20;
		running->max_packet_que = 60;
		running->max_tracked_ttl = 1024;

		/* default is to set port in normal aggressivity */
		memset(running->portconf, NORMAL, PORTNUMBER);

		/* hacks to be fixed */
		running->SjH__shift_ack = false;			/* implemented, need testing */
		running->SjH__half_fake_syn = false;			/* currently not implemented */
		running->SjH__half_fake_ack = false;			/* currently not implemented */

		/* hacks common defaults */
		running->SjH__fake_data = false;			/* implemented, enabled */
		running->SjH__fake_seq = false;				/* implemented, enabled */
		running->SjH__fake_close = false;			/* implemented, enabled */
		running->SjH__zero_window = false;			/* implemented, enabled */
		running->SjH__valid_rst_fake_seq = false;		/* implemented, enabled */
		running->SjH__fake_syn = false;				/* implemented, enabled */
		running->SjH__inject_ipopt = false;			/* implemented, enabled */
		running->SjH__inject_tcpopt = false;			/* implemented, enabled */
	}
	
	/* Read command line values if present */
	if(user_opt->user != NULL) {
		strncpy(running->user, user_opt->user, SMALLBUF);
		running->user[SMALLBUF - 1] = '\0';
	}
	if(user_opt->group != NULL) {
	strncpy(running->group, user_opt->group, SMALLBUF);
	running->group[SMALLBUF - 1] = '\0';
	}
	if(user_opt->chroot_dir != NULL) {
		strncpy(running->chroot_dir, user_opt->chroot_dir, MEDIUMBUF);
		running->chroot_dir[MEDIUMBUF - 1] = '\0';
	}
	if(user_opt->logfname != NULL) {
		strncpy(running->logfname, user_opt->logfname, MEDIUMBUF);
		running->logfname[MEDIUMBUF - 1] = '\0';	
	}
	if(user_opt->debug_level != -1)
		running->debug_level = user_opt->debug_level;

	dump_config(user_opt->cfgfname);
}

SjConf::~SjConf() {
	internal_log(NULL, ALL_LEVEL, "SjConf: cleaning configuration object\n");
}

void SjConf::dump_config(const char *dumpfname)
{
	FILE *dumpfd;
	int ret;
	float magic_value = (MAGICVAL * 28.26);

	running->MAGIC = magic_value;

	dumpfd = fopen(dumpfname, "w");
	check_call_ret("open config file in writing", errno, dumpfd == NULL ? -1 : 0, false);

	ret = fwrite(running, sizeof(struct sj_config), 1, dumpfd);
	/* ret - 1 because fwrite return the number of written item */
	check_call_ret("writing config file", errno, (ret - 1), false);

	fclose(dumpfd);
	check_call_ret("closing config file", errno, (ret - 1), false);
}

char *SjConf::handle_stat_command(void) 
{
	internal_log(NULL, VERBOSE_LEVEL, "stat command requested");
	snprintf(io_buf, HUGEBUF, 
		"sniffjoke running:\t\t%s\n" \
		"gateway mac address:\t\t%s\n" \
		"gateway ip address:\t\t%s\n" \
		"local interface:\t\t%s, %s address\n" \
		"dynamic tunnel interface:\ttun%d",
		running->sj_run == true ? "TRUE" : "FALSE",
		running->gw_mac_str,
		running->gw_ip_addr,
		running->interface, running->local_ip_addr,
		running->tun_number
	);
	return &io_buf[0];
}

char *SjConf::handle_set_command(unsigned short start, unsigned short end, unsigned char what)
{
	const char *what_weightness;

	switch(what) {
		case HEAVY: what_weightness = "heavy"; break;
		case NORMAL: what_weightness = "normal"; break;
		case LIGHT: what_weightness = "light"; break;
		case NONE: what_weightness = "no hacking"; break;
		default: 
			snprintf(io_buf, HUGEBUF, "ERROR!! invalid code (0x%2x) in %s:%s:%d", what, __FILE__, __func__, __LINE__);
			internal_log(NULL, ALL_LEVEL, "BAD ERROR: %s", io_buf);
			return &io_buf[0];
			break;
	}

	snprintf(io_buf, HUGEBUF, "set ports from %d to %d at [%s] level", start, end, what_weightness);
	internal_log(NULL, ALL_LEVEL, "%s", io_buf);

	do {
		running->portconf[start] = what;
		start++;
	} while(start <= end);

	return &io_buf[0];
}

char *SjConf::handle_stop_command(void)
{
	if(running->sj_run != false) {
		snprintf(io_buf, HUGEBUF, "stopped sniffjoke as requested!");
		internal_log(NULL, ALL_LEVEL, "%s", io_buf);
		running->sj_run = false;
	} else /* sniffjoke is already stopped */ {
		snprintf(io_buf, HUGEBUF, "received stop request, but sniffjoke is already stopped!");
		internal_log(NULL, ALL_LEVEL, "%s", io_buf);
	}
	return &io_buf[0];
}

char *SjConf::handle_start_command(void)
{
	if(running->sj_run != true) {
		snprintf(io_buf, HUGEBUF, "started sniffjoke as requested!");
		internal_log(NULL, ALL_LEVEL, "%s", io_buf);
		running->sj_run = true;
	} else /* sniffjoke is already running */ {
		snprintf(io_buf, HUGEBUF, "received start request, but sniffjoke is already running!");
		internal_log(NULL, ALL_LEVEL, "%s", io_buf);
	}
	return &io_buf[0];
}

/* private function useful for resolution of code/name */
const char *SjConf::resolve_weight_name(int command_code) 
{
	switch(command_code) {
		case HEAVY: return "heavy";
		case NORMAL: return "normal";
		case LIGHT: return "light";
		case NONE: return "no hacks";
		default: internal_log(NULL, ALL_LEVEL, "danger: found invalid code in ports configuration");
			 return "VERY BAD BUFFER CORRUPTION! I WISH NO ONE EVER SEE THIS LINE";
	}
}

char *SjConf::handle_showport_command(void) 
{
	int i, acc_start = 0, acc_end = 0, kind, actual_io = 0;
	char *index = &io_buf[0];
	memset(io_buf, 0x00, HUGEBUF);

	/* the first port work as initialization */
	kind = running->portconf[0];

	for(i = 1; i < PORTNUMBER; i++) {
		/* the kind has changed, so we must print the previous port range */
		if(running->portconf[i] != kind) 
		{
			if( acc_start == ( i - 1) ) 
				snprintf(index, HUGEBUF - actual_io, "%s\tdest port: %d\n", resolve_weight_name(kind), acc_start);
			else
				snprintf(index, HUGEBUF - actual_io, "%s\tdest ports: %d:%d\n", resolve_weight_name(kind), acc_start, i - 1);

			actual_io = strlen(io_buf);
			index = &io_buf[actual_io];

			kind = running->portconf[i];
			acc_start = i;
		}
	}

	snprintf(index, HUGEBUF - actual_io, "%s\t dest ports %d:65535\n", resolve_weight_name(kind), acc_start);

	return &io_buf[0];
}

char *SjConf::handle_log_command(int newloglevel)
{
	snprintf(io_buf, HUGEBUF, "TO BE IMPLEMENTED -- new log level requested %d\n", newloglevel);
	return &io_buf[0];
}
