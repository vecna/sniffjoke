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
	check_call_ret("open config file in writing", errno, dumpfd == NULL ? -1 : 0);

	printf(	"* saving configuration settings in file [%s]:\n"
		"  + sniffjoke running:\t%s\n"
		"  + gateway mac addr:\t%s\n"
		"  + gateway ip addr:\t%s\n"
		"  + network interface:\t%s\n"
		"  + ip address of %s:\t%s\n"
		"  + tunnel interface:\ttun%d\n",
		dumpfname,
		running->sj_run == true ? "TRUE" : "FALSE",
		running->gw_mac_str, 
		running->gw_ip_addr, 
		running->interface,
		running->interface,
		running->local_ip_addr,
		running->tun_number
	);

	ret = fwrite(running, sizeof(struct sj_config), 1, dumpfd);
	/* ret - 1 because fwrite return the number of written item */
	check_call_ret("writing config file", errno, ret - 1);

	fclose(dumpfd);
}

void SjConf::dump_error(char *errstring, int errlength)
{
	running->error =(char *)malloc(errlength +1);
	memcpy(running->error, errstring, errlength);
	running->error[errlength] = 0x00;
	printf("reporting error in configuration params: %s\n", running->error);
}

SjConf::SjConf(const char *confname, /* FIXME struct cmdline_opt *useropt */ unsigned short web_bind_port ) 
{
	float magic_check = (MAGICVAL * 28.26);
	FILE *cF;
	int i;

	running = (struct sj_config *)malloc(sizeof(struct sj_config));
	
	if((cF = fopen(confname, "r")) != NULL) 
	{
		struct sj_config readed;

		memset(&readed, 0x00, sizeof(struct sj_config));

		i = fread((void *)&readed, sizeof(struct sj_config), 1, cF);
		check_call_ret("fread of config file", errno, i - 1);

		if(readed.MAGIC != magic_check) 
			check_call_ret("invalid checksum of config file", 0, -1);

		printf(	"readed configuration settings from file [%s] with parameters:\n"
			"  + sniffjoke running:\t%s\n"
			"  + gateway mac addr:\t%s\n"
			"  + gateway ip addr:\t%s\n"
			"  + network interface:\t%s\n"
			"  + ip address of %s:\t%s\n"
			"  + tunnel interface:\ttun%d\n",
			confname,
			readed.sj_run == true ? "TRUE" : "FALSE",
			readed.gw_mac_str, 
			readed.gw_ip_addr, 
			readed.interface,
			readed.interface,
			readed.local_ip_addr,
			readed.tun_number
		);

		fclose(cF);

		memcpy(running, &readed, sizeof(sj_config));
	}
	else {
		unsigned int i;
		FILE *foca;
		char imp_str[SMALLBUF];

		const char *cmd0 = "ifconfig -a | grep tun | cut -b -7";
		const char *cmd1 = "grep 0003 /proc/net/route | grep 00000000 | cut -b -7";
		char cmd2[MEDIUMBUF];
		const char *cmd3 = "route -n | grep UG | cut -b 17-32";
		char cmd4[MEDIUMBUF];
		
		printf("configuration file [%s] invalid (%s), setting up new\n", confname, strerror(errno));

		/* set up default before wait the "start sniffjoke" from web panel */
		memset(running, 0x00, sizeof(sj_config));

		/* autodetecting first tunnel device free */
		printf("* detecting first free tunnel device with [%s]\n", cmd0);
		foca = popen(cmd0, "r");
		for(running->tun_number = 0; ; running->tun_number++)
		{
			memset(imp_str, 0x00, SMALLBUF);
			fgets(imp_str, SMALLBUF, foca);

			if(imp_str[0] == 0x00)
				break;
		}
		pclose(foca);
		printf("  + detected %d as first free tunnel device\n", running->tun_number);

		/* autodetecting interface */
		printf("* detecting external gateway interface with [%s]\n", cmd1);
		foca = popen(cmd1, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && isalnum(imp_str[i]); i++)
			running->interface[i] = imp_str[i];

		if(i < 3) {
			printf("  - unable to acquire external interface with a default gw, set up manually\n");
			goto endofautodetect;
		}
		else 
			printf("  + automatically acquired interface [%s]\n", running->interface);
		
		/* autodetecting interface local ip address */
		snprintf(cmd2, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21-", 
			running->interface
		);
		printf("* detecting interface %s ip address with [%s]\n",
			running->interface, cmd2
		);
		foca = popen(cmd2, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isdigit(imp_str[i]) || imp_str[i] == '.' ); i++)
			running->local_ip_addr[i] = imp_str[i];

		printf("  + automatically acquired local ip address [%s]\n", running->local_ip_addr);

		/* autodetecting gw ip addr */
		printf("* detecting gateway ip address with [%s]\n", cmd3);
		foca = popen(cmd3, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isdigit(imp_str[i]) || imp_str[i] == '.' ); i++) 
			running->gw_ip_addr[i] = imp_str[i];

		if(strlen(running->gw_ip_addr) < 7) {
			printf("  - unable to autodetect gateway ip address, set up manually\n");
			goto endofautodetect;
		}
		else 
			printf("  + automatically acquired gateway ip address [%s]\n", running->gw_ip_addr);

		/* autodetecting mac address */
		snprintf(cmd4, MEDIUMBUF, "ping -W 1 -c 1 %s", running->gw_ip_addr);
		printf("* pinging %s for make sure ARP presence with [%s]\n", 
			running->gw_ip_addr,
			cmd4
		);
		system(cmd4);
		usleep(50000);
		memset(cmd4, 0x00, MEDIUMBUF);

		snprintf(cmd4, MEDIUMBUF, "arp -n | grep %s | cut -b 34-50", running->gw_ip_addr);
		printf("* detecting mac address of gateway with [%s]\n", cmd4);
		foca = popen(cmd4, "r");
		fgets(imp_str, SMALLBUF, foca);
		pclose(foca);

		for(i = 0; i < strlen(imp_str) && ( isxdigit(imp_str[i]) || imp_str[i] == ':' ); i++)
			running->gw_mac_str[i] = imp_str[i];

		if(i != 17) 
			printf("  - unable to autodetect gateway mac address\n");
		else {
			printf("  + automatically acquired mac address [%s]\n\n", running->gw_mac_str);
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
		running->web_bind_port = /* FIXME useropt->*/web_bind_port;
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
