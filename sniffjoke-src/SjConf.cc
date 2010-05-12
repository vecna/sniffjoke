#include <iostream>
#include <cerrno>
using namespace std;
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "sniffjoke.h"

void SjConf::dump_config(const char *dumpfname)
{
	FILE *dumpfd;
	int ret;
	float magic_value = (MAGICVAL * 28.26);

	running->MAGIC = magic_value;

	dumpfd = fopen(dumpfname, "w+");
	check_call_ret("open config file in writing", errno, dumpfd == NULL ? -1 : 0, false);

	internal_log(NULL, ALL_LEVEL, "saving configuration settings in %s", dumpfname);
	internal_log(NULL, ALL_LEVEL, "-- sniffjoke running: %s", running->sj_run == true ? "TRUE" : "FALSE");
	internal_log(NULL, ALL_LEVEL, "-- sniffjoke gateway mac address: %s", running->gw_mac_str);
	internal_log(NULL, ALL_LEVEL, "-- sniffjoke gateway ip address: %s", running->gw_ip_addr);
	internal_log(NULL, ALL_LEVEL, "-- sniffjoke local interface: %s, %s address", running->interface, running->local_ip_addr);
	internal_log(NULL, ALL_LEVEL, "-- sniffjoke dynamic tunnel interface: tun%d", running->tun_number);

	ret = fwrite(running, sizeof(struct sj_config), 1, dumpfd);
	/* ret - 1 because fwrite return the number of written item */
	check_call_ret("writing config file", errno, (ret - 1), false);

	fclose(dumpfd);
	check_call_ret("closing config file", errno, (ret - 1), false);
}

SjConf::SjConf(struct sj_useropt *user_opt) 
{
	float magic_check = (MAGICVAL * 28.26);
	FILE *cF;
	int i;

	running = (struct sj_config *)malloc(sizeof(struct sj_config));
	
	internal_log(NULL, DEBUG_LEVEL, "opening configuration file: %s", user_opt->cfgfname);
	if((cF = fopen(user_opt->cfgfname, "r")) != NULL) 
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

		internal_log(NULL, ALL_LEVEL, "readed configuration settings in %s", user_opt->cfgfname);
		internal_log(NULL, ALL_LEVEL, "-- sniffjoke running: %s", readed.sj_run == true ? "TRUE" : "FALSE");
		internal_log(NULL, ALL_LEVEL, "-- sniffjoke gateway mac address: %s", readed.gw_mac_str);
		internal_log(NULL, ALL_LEVEL, "-- sniffjoke gateway ip address: %s", readed.gw_ip_addr);
		internal_log(NULL, ALL_LEVEL, "-- sniffjoke local interface: %s, %s address", readed.interface, readed.local_ip_addr);
		internal_log(NULL, ALL_LEVEL, "-- sniffjoke dynamic tunnel interface: tun%d", readed.tun_number);

		fclose(cF);

		memcpy(running, &readed, sizeof(sj_config));
		
	} else {
		
		unsigned int i;
		FILE *foca;
		char imp_str[SMALLBUF];

		const char *cmd0 = "ifconfig -a | grep tun | cut -b -7";
		const char *cmd1 = "grep 0003 /proc/net/route | grep 00000000 | cut -b -7";
		char cmd2[MEDIUMBUF];
		const char *cmd3 = "route -n | grep ^0.0.0.0 | cut -b 17-32"; 
		char cmd4[MEDIUMBUF];
	
		internal_log(NULL, ALL_LEVEL, "configuration file %s invalid (%s), creating new configuration...", 
			user_opt->cfgfname, strerror(errno)
		);

		/* set up default before wait the "start sniffjoke" from web panel */
		memset(running, 0x00, sizeof(sj_config));

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
		internal_log(NULL, ALL_LEVEL, "== detected %d as first unused tunnel device", running->tun_number);

		/* autodetecting interface */
		internal_log(NULL, ALL_LEVEL, "++ detecting external gateway interface with [%s]", cmd1);
		foca = popen(cmd1, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && isalnum(imp_str[i]); i++)
			running->interface[i] = imp_str[i];

		if(i < 3) {
			internal_log(NULL, ALL_LEVEL, "unable to detect external default gw: set up manually");
			goto endofautodetect;
		}
		else {
			internal_log(NULL, ALL_LEVEL, "== detected external interface with default gateway: %s", running->interface);
		}
		
		/* autodetecting interface local ip address */
		snprintf(cmd2, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21-", 
			running->interface
		);
		internal_log(NULL, ALL_LEVEL, "++ detecting interface %s ip address with [%s]", running->interface, cmd2);

		foca = popen(cmd2, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isdigit(imp_str[i]) || imp_str[i] == '.' ); i++)
			running->local_ip_addr[i] = imp_str[i];

		internal_log(NULL, ALL_LEVEL, "== acquired local ip address: %s", running->local_ip_addr);

		/* autodetecting gw ip addr */
		internal_log(NULL, ALL_LEVEL, "++ detecting gateway ip address with [%s]", cmd3);
		foca = popen(cmd3, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isdigit(imp_str[i]) || imp_str[i] == '.' ); i++) 
			running->gw_ip_addr[i] = imp_str[i];

		if(strlen(running->gw_ip_addr) < 7) {
			internal_log(NULL, ALL_LEVEL, "-- unable to autodetect gateway ip address, set up manually");
			goto endofautodetect;
		}
		else 
			internal_log(NULL, ALL_LEVEL, "== automatically acquired gateway ip address: %s", running->gw_ip_addr);

		/* autodetecting mac address */
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

		if(i != 17) 
			internal_log(NULL, ALL_LEVEL, "-- unable to autodetect gateway mac address");
		else {
			internal_log(NULL, ALL_LEVEL, "== automatically acquired mac address: %s", running->gw_mac_str);
			sscanf( running->gw_mac_str, "%hX:%hX:%hX:%hX:%hX:%hX",
				&running->gw_mac_addr[0], &running->gw_mac_addr[1], 
				&running->gw_mac_addr[2], &running->gw_mac_addr[3], 
				&running->gw_mac_addr[4], &running->gw_mac_addr[5]
			);
		}
		
		
endofautodetect:

		/* setting common defaults */
		running->sj_run = 0;
		running->max_session_tracked = 20;
		running->max_packet_que = 60;
		running->max_tracked_ttl = 1024;
		running->MAGIC = magic_check;
		running->web_bind_port = user_opt->bind_port;
		running->max_ttl_probe = 26;
		
		/* hacks common defaults */
		running->SjH__shift_ack = false;		/* implemented, need testing */
		running->SjH__fake_data = true;			/* implemented, enabled */
		running->SjH__fake_seq = true;			/* implemented, enabled */
		running->SjH__fake_close = true;		/* implemented, enabled */
		running->SjH__zero_window = true;		/* implemented, enabled */
		running->SjH__valid_rst_fake_seq = true;	/* implemented, enabled */
		running->SjH__fake_syn = true;			/* implemented, enabled */
		running->SjH__half_fake_syn = false;		/* currently not implemented */
		running->SjH__half_fake_ack = false;		/* currently not implemented */
		running->SjH__inject_ipopt = true;		/* implemented, enabled */
		running->SjH__inject_tcpopt = true;		/* implemented, enabled */
	}

	running->reload_conf = true;
}

SjConf::~SjConf() {
	printf("SjConf: cleaning configuration object\n");
}
