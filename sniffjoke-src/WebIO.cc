#include <iostream>
#include <cerrno>
#include <string.h>
using namespace std;
#include <stdio.h>
#include <stdlib.h>

/* original source http://swill.sourceforge.net/ */
#include <swill/swill.h>
#include "sniffjoke.hh"

static sj_config *runcopy_static;

static char *default_creat(const char *tb, struct sj_config *runcopy)
{
	/* SJK'*': 
	 *	B: bind port
	 *	I: interface
	 *	M: mac address
	 *	G: gateway ip
	 *	T: max ttl bruteforce
	 *	L: local ip address
	 *	N: tunnel interface number
	 *	S: status (running or not)
 	 */
	static char ret[GARGANTUABUF];
	const char *tm="SJK";
	const char *ok ="Sniffjoke <b>IS RUNNING</b>: <br><br><img src='images/full_img_sj_on.jpg' />";
	const char *ko ="Sniffjoke <b>IS NOT</b> running: <br><br><img src='images/full_img_sj_off.jpg' />";
	int i, x =0;

	for(i =0; i < (int)strlen(tb); i++) 
	{
		int l;

		if((int)strlen(tb) > (i - 4) && (! memcmp(&tb[i], tm, 3)) ) 
		{
			switch(tb[i + 3]) {
				case 'B':
					l =sprintf(&ret[x], "%d", runcopy->web_bind_port);
					x += l;
					break;
				case 'I':
					l =sprintf(&ret[x], "%s", runcopy->interface);
					x += l;
					break;
				case 'M':
					l =sprintf(&ret[x], "%s", runcopy->gw_mac_str);
					x += l;
					break;
				case 'G':
					l =sprintf(&ret[x], "%s", runcopy->gw_ip_addr);
					x += l;
					break;
				case 'T':
					l =sprintf(&ret[x], "%d", runcopy->max_ttl_probe);
					x += l;
					break;
				case 'L':
					l =sprintf(&ret[x], "%s", runcopy->local_ip_addr);
					x += l;
					break;
				case 'N':
					l =sprintf(&ret[x], "%d", runcopy->tun_number);
					x += l;
					break;
				case 'S': /* sniffjoke status */
					if(runcopy->sj_run == 1) 
						l =sprintf(&ret[x], "%s", ok);
					else
						l =sprintf(&ret[x], "%s", ko);
					x += l;
					break;
				default:
					printf("default %s:%d ?\n", __FILE__, __LINE__);
			}
			i +=4;
		}
		ret[x] = tb[i];
		x++;
	}
	return ret;
}


static char * sysinfo_creat(const char *tb, struct sj_config *runcopy)
{
	/* arp -a = SJSTR0, route -n = SJSTR1, ecc... */
	const char *cmd[]={ "arp -a", "route -n", "ifconfig -a" };
	static char ret[GARGANTUABUF];
	int i, x = 0;
	const char *tm="SJSTR";

	for(i =0; i < (int)strlen(tb); i++) {

		if((int)strlen(tb) > (i - 5) && (! memcmp(&tb[i], tm, 5)) )
		{
			FILE *foca;
			int imp_char;

			i += 5;
			foca = popen(cmd[(int)tb[i] - 48], "r");
			while( (imp_char = fgetc(foca)) != EOF) 
			{
				ret[x] = (char)imp_char;
				x++;

				if(x == GARGANTUABUF) {
					printf("AARGH! execution of %s give an output > than %d byte!\n",
						cmd[(int)tb[i] - 48], x
					);
					break;
				}
			}
			pclose(foca);
		}
		else {
			ret[x] = tb[i];
			x++;
		}
	}

	return ret;
}

static char * sniffjoke_status(struct sj_config *runcopy)
{
	static char ret[HUGEBUF];
	const char *intro="Error detected: ";

	memset(ret, 0x00, HUGEBUF);

	if(runcopy->error !=NULL) {
		int off = strlen(intro) -1;

		memcpy(ret, intro, strlen(intro));
		memcpy(&ret[off], runcopy->error, strlen(runcopy->error));
	}

	return ret;
}

static void import_get_vars(
	int R_wbp, int R_mtp, int R_start, int R_stop,
	char *R_i, char *R_gia, char *R_gma, 
	struct sj_config *runcopy
)
{
	/* is button start set ? */
	if(R_start != 0)
		runcopy->sj_run = 1;
	if(R_stop != 0)
		runcopy->sj_run = 0;

	/* import weblocal conf */
	if(R_wbp != 0) 
		runcopy->web_bind_port = R_wbp;
	else
		runcopy->sj_run = 0;
		
	if(R_mtp != 0)
		runcopy->max_ttl_probe = R_mtp;
	else 
		runcopy->max_ttl_probe = 30;

	if(R_gia != NULL) {
		memset( runcopy->gw_ip_addr, 0x00, SMALLBUF);
		memcpy( runcopy->gw_ip_addr, R_gia, strlen(R_gia));
	}
	else {
		char *swp =(char *)"gw IP";
		memcpy(runcopy->gw_ip_addr, swp, strlen(swp));
		runcopy->sj_run = 0;
	}

	if(R_i != NULL) {
		memset( runcopy->interface, 0x00, SMALLBUF);
		memcpy( runcopy->interface, R_i, (strlen(R_i) > SMALLBUF) ? SMALLBUF : strlen(R_i) );
	}
	else {
		char *swp= (char *)"interface";
		/* interface is char[18] */
		memcpy(runcopy->interface, swp, strlen(swp));
		runcopy->sj_run = 0;
	}

	/* import mac address without check */
	if(R_gma != NULL ) 
	{
		memcpy( runcopy->gw_mac_str, R_gma, 
			(strlen(R_gma) > SMALLBUF) ? SMALLBUF : strlen(R_gma) 
		);
		sscanf( runcopy->gw_mac_str, "%hX:%hX:%hX:%hX:%hX:%hX",
			&runcopy->gw_mac_addr[0], &runcopy->gw_mac_addr[1], &runcopy->gw_mac_addr[2],
			&runcopy->gw_mac_addr[3], &runcopy->gw_mac_addr[4], &runcopy->gw_mac_addr[5]
		);
	}
}
		
static void print_sniffjoke_page(FILE *out, struct sj_config *runcopy)
{
	const char *html_head="<html><head><title>Sniffjoke Configuration page</title>\n"
			"<link rel='stylesheet' href='sniffjoke.css' type='text/css'>\n"
			"</head><body><form name='sjform' method=GET>";

	const char *html_epilogue ="<br><br>bye</form></body></html>";

	const char *title_open="<div class='titolo'>";
	const char *title_close="</div>";

	const char *text_open="<div class='testo'>";
	const char *text_close="</div>";

	const char *title[] = {
"Sniffjoke diagnostic",
"Sniffjoke configuration section",
"System diagnostics",
"Sniffjoke statistics"
	};

	const char *section[] = {
	/* sniffjoke configuration html block */
"<center>\n"
"SJKS<br><br>\n" /* SJKS contains SniffJoke Status */
"<button name='start' value='1' type='SUBMIT'>start sniffjoke</button>\n"
"<button name='stop' value='1' type='SUBMIT'>stop sniffjoke</button>\n"
"</center><br><br>\n"
"<input name='web_bind_port' value='SJKB'>Local TCP port for SniffJoke administration<br>\n"
"<input name='interface' value='SJKI'>external network interface<br>\n"
"<input name='gw_ip_addr' value='SJKG'>Ip address of gateway<br>\n"
"<input name='gw_mac_str' value='SJKM'>Gateway mac address<br>\n"
"<input name='local_ip_addr' value='SJKL'>Local ip address<br>\n"
"<input name='tun_number' value='SJKN'>tunnel interface number<br>\n"
"<input name='max_ttl_probe' value='SJKT'>Maximum number of probe for discern TTL/HOP distance<br>\n",

	/* system info and network stats */
"arp table <b>(useful for copypaste the gw mac address :)</b>\n"
"<pre>SJSTR0</pre>\n"
"routing table\n"
"<pre>SJSTR1</pre>\n"
"network interface\n"
"<pre>SJSTR2</pre>\n",

	/* link to documentation and discussions about sniffjoke */
"<center>No statistics implemented at the moment</center>"
"Sniffjoke web page <a href='http://www.delirandom.net/sniffjoke'>here (delirandom.net)</a><br>"
"Sniffjoke local documentation <a href='sniffjoke_info.html'>here</a>"
	};

	fprintf(out, "%s\n", html_head);

	fprintf(out, "%s %s %s  \n", title_open, title[0], title_close);
	fprintf(out, "%s %s %s  \n", text_open, sniffjoke_status(runcopy), text_close);

	fprintf(out, "%s %s %s  \n", title_open, title[1], title_close);
	fprintf(out, "%s %s %s  \n", text_open, default_creat(section[0], runcopy), text_close);

	fprintf(out, "%s %s %s  \n", title_open, title[2], title_close);
	fprintf(out, "%s %s %s  \n", text_open, sysinfo_creat(section[1], runcopy), text_close);

	fprintf(out, "%s %s %s  \n", title_open, title[3], title_close);
	fprintf(out, "%s %s %s  \n", text_open, section[2], text_close);

	fprintf(out, "%s\n", html_epilogue);
}

static void sniffjoke_handler(FILE *out) 
{
	struct sj_config *runcopy = (struct sj_config *)runcopy_static;

	int R_wbp = 0, R_mtp = 0, R_start =0, R_stop =0;
	char *R_i =NULL, *R_gia =NULL, *R_gma =NULL;

	swill_getargs("|i(start)i(stop)i(web_bind_port)s(interface)s(gw_ip_addr)s(gw_mac_str)i(max_ttl_probe)", &R_start, &R_stop, &R_wbp, &R_i, &R_gia, &R_gma, &R_mtp);

	if(R_gia != NULL && R_i != NULL && R_wbp != 0) {
		/* import HTTP GET input and check integrity */
		import_get_vars(R_wbp, R_mtp, R_start, R_stop, R_i, R_gia, R_gma, runcopy);
		/* answer with a page that sleep for 1 second and recall sniffjoke.html
 		 * without argument, changine che code flow in the next iteration, calling
 		 * print_sniffjoke_page */
		fprintf(out, "<html><head><META http-equiv=\"refresh\" content=\"1;"
			     "URL=http://127.0.0.1:%d/sniffjoke.html\"></head><center><h3>"
			      "refresh: 1 second for new configuration",
			      runcopy->web_bind_port
		);
	}
	else
		print_sniffjoke_page(out, runcopy);

}

static void sniffjoke_help(FILE *out) 
{
	struct sj_config *runcopy = (struct sj_config *)runcopy_static;
	const char *help = "<html><head><META http-equiv=\"refresh\" content=\"1;"
			   "URL=http://127.0.0.1:SJKB/sniffjoke.html\"></head><center><h3>"
			   "refreshing to sniffjoke configuration page...";

	fprintf(out, " %s ", default_creat(help, runcopy) );
}

WebIO::WebIO( SjConf *sjc ) 
{
	runcopy_static = sjc->running;

	if(swill_init(runcopy_static->web_bind_port) != runcopy_static->web_bind_port) 
		check_call_ret("Unable to bind webserver", errno, -1);

	swill_allow("127.0.0.1");

	swill_handle("sniffjoke.html", sniffjoke_handler, NULL );
	swill_handle("index.html", sniffjoke_help, NULL );

	swill_file("sniffjoke.css", 0);
	swill_file("sniffjoke_info.html", 0);
	swill_file("images/full_img_sj_on.jpg", 0);
	swill_file("images/full_img_sj_off.jpg", 0);
	swill_file("images/alice_sj.jpg", 0);
	swill_file("images/bob_sj.jpg", 0);
	swill_file("images/hero_sj.jpg", 0);
	swill_file("images/eve_sj.jpg", 0);
	swill_file("images/visualroute.gif", 0);
}

WebIO::~WebIO() {
	printf("WebIO: cleaning swill instance...\n");
	swill_shutdown();
}

int WebIO::web_poll() {
	return swill_poll();
}
