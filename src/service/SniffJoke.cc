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

#include "SniffJoke.h"

#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

SniffJoke::SniffJoke(struct sj_cmdline_opts &opts) :
alive(true),
opts(opts),
userconf(opts),
proc(userconf.runconfig),
service_pid(0)
{
    debug_setup(stdout);
    debug.log(VERBOSE_LEVEL, __func__);
}

SniffJoke::~SniffJoke()
{
    if (getuid() || geteuid())
    {
        debug.log(DEBUG_LEVEL, "Service with users privileges: %s [%d]", __func__, getpid());
        server_user_cleanup();
    }
    else
    {
        debug.log(DEBUG_LEVEL, "Service with root privileges: %s [%d]", __func__, getpid());
        server_root_cleanup();
    }
    /* closing the log files */
    debug_cleanup();
}

void SniffJoke::run()
{
    pid_t old_service_pid = proc.readPidfile();
    if (old_service_pid != 0)
    {
        if (!opts.force_restart)
        {
            debug.log(ALL_LEVEL, "SniffJoke is already runconfig, use --force or check --help");
            debug.log(ALL_LEVEL, "the pidfile %s contains the apparently running pid: %d", SJ_PIDFILE, old_service_pid);
            return;
        }
        else
        {
            debug.log(VERBOSE_LEVEL, "forcing exit of previous running service %d ...", old_service_pid);

            /* we have to do quite the same as in sniffjoke_server_cleanup,
             * but relative to the service_pid read with readPidfile;
             * here we can not use the waitpid because the process to kill it's not a child of us;
             * we can use a sleep(2) instead. */
            kill(old_service_pid, SIGTERM);
            sleep(2);
            proc.unlinkPidfile(true);
            debug.log(ALL_LEVEL, "A new instance of SniffJoke is going background");
        }
    }

    if (!old_service_pid && opts.force_restart)
        debug.log(VERBOSE_LEVEL, "option --force ignore: not found a previously running SniffJoke");

    if (!userconf.runconfig.active)
        debug.log(ALL_LEVEL, "SniffJoke is INACTIVE: use \"sniffjoke start\" command to start it");
    else
        debug.log(VERBOSE_LEVEL, "SniffJoke resumed as ACTIVE");

    /* we run the network setup before the background, to keep the software output visible on the console */
    userconf.network_setup();

    if (!opts.go_foreground)
    {
        proc.background();

        /* Log Object must be reinitialized after background and before the chroot! */
        debug_setup(NULL);

        proc.isolation();
    }

    /* the code flow reach here, SniffJoke is ready to instance network environment */
    mitm = auto_ptr<NetIO > (new NetIO(userconf.runconfig));

    /* sigtrap handler mapped the same in both Sj processes */
    proc.sigtrapSetup(sigtrap);

    /* proc.detach: fork() into two processes,
       from now on the real configuration is the one mantained by the child */
    service_pid = proc.detach();

    /* this is the root privileges thread, need to run for restore the network
     * environment in shutdown */
    if (service_pid)
    {
        int deadtrace;

        proc.writePidfile();
        if (waitpid(service_pid, &deadtrace, WUNTRACED) > 0)
        {

            if (WIFEXITED(deadtrace))
                debug.log(VERBOSE_LEVEL, "child %d WIFEXITED", service_pid);
            if (WIFSIGNALED(deadtrace))
                debug.log(VERBOSE_LEVEL, "child %d WIFSIGNALED", service_pid);
            if (WIFSTOPPED(deadtrace))
                debug.log(VERBOSE_LEVEL, "child %d WIFSTOPPED", service_pid);
        }
        else
        {
            debug.log(VERBOSE_LEVEL, "child waitpid failed with: %s", strerror(errno));
        }

        debug.log(DEBUG_LEVEL, "child %d died, going to shutdown", service_pid);

    }
    else
    {

        /* loading the plugins used for tcp hacking, MUST be done before proc.jail() */
        hack_pool = auto_ptr<HackPool > (new HackPool(userconf.runconfig));

        /* proc.jail: chroot + userconf.runconfig.chrooted = true */
        proc.jail(userconf.runconfig.chroot_dir);
        userconf.chroot_status = true;

        proc.privilegesDowngrade();

        sessiontrack_map = auto_ptr<SessionTrackMap > (new SessionTrackMap);
        ttlfocus_map = auto_ptr<TTLFocusMap > (new TTLFocusMap(FILE_TTLFOCUSMAP));
        conntrack = auto_ptr<TCPTrack > (new TCPTrack(userconf.runconfig, *hack_pool, *sessiontrack_map, *ttlfocus_map));

        mitm->prepare_conntrack(conntrack.get());

        admin_socket_setup();

        /* main block */
        while (alive)
        {

            sj_clock = time(NULL);

            proc.sigtrapDisable();

            mitm->network_io();

            admin_socket_handle();

            proc.sigtrapEnable();

            userconf.dump();
        }
    }
}

void SniffJoke::debug_setup(FILE *forcedoutput) const
{
    debug.debuglevel = userconf.runconfig.debug_level;

    /* when sniffjoke start force the output to be stdout */
    if (forcedoutput != NULL)
    {
        debug.logstream = forcedoutput;
        return;
    }

    if (!opts.go_foreground)
    {
        /* Logfiles are used only by a Sniffjoke SERVER runnning in background */
        if (!debug.resetLevel())
            SJ_RUNTIME_EXCEPTION("Error in opening log files");
    }
    else /* userconf.runconfig.go_foreground */
    {
        debug.logstream = stdout;
        debug.log(ALL_LEVEL, "forground logging enable, use ^c for quit SniffJoke");
    }
}

/* this function must not close the FILE *desc, because in the destructor of the
 * auto_ptr some debug call will be present. It simple need to flush the FILE,
 * and the descriptor are closed with the process, after. */
void SniffJoke::debug_cleanup()
{
    if (debug.logstream != NULL && debug.logstream != stdout)
        fflush(debug.logstream);
    if (debug.packet_logstream != NULL && debug.packet_logstream != stdout)
        fflush(debug.packet_logstream);
    if (debug.session_logstream != NULL && debug.session_logstream != stdout)
        fflush(debug.session_logstream);
}

void SniffJoke::server_root_cleanup()
{
    if (service_pid)
    {
        debug.log(VERBOSE_LEVEL, "server_root_cleanup() %d", service_pid);
        kill(service_pid, SIGTERM);
        waitpid(service_pid, NULL, WUNTRACED);
    }

    proc.unlinkPidfile(false);
}

void SniffJoke::server_user_cleanup()
{
    debug.log(VERBOSE_LEVEL, "client_user_cleanup()");
}

void SniffJoke::admin_socket_setup()
{
    int tmp;
    struct sockaddr_in in_service;

    if ((tmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        debug.log(ALL_LEVEL, "FATAL: unable to open UDP socket: %s", strerror(errno));
        SJ_RUNTIME_EXCEPTION("");
    }

    memset(&in_service, 0x00, sizeof (in_service));
    /* here we are running under chroot, resolution will not work without /etc/hosts and /etc/resolv.conf */
    if (!inet_aton(userconf.runconfig.admin_address, &in_service.sin_addr))
    {
        debug.log(ALL_LEVEL, "Unable to accept hostname (%s): only IP address allow", userconf.runconfig.admin_address);
        SJ_RUNTIME_EXCEPTION("");
    }
    in_service.sin_family = AF_INET;
    in_service.sin_port = htons(userconf.runconfig.admin_port);

    if (bind(tmp, (struct sockaddr *) &in_service, sizeof (in_service)) == -1)
    {
        close(tmp);
        debug.log(ALL_LEVEL, "FATAL ERROR: unable to bind UDP socket %s:%d: %s",
                  userconf.runconfig.admin_address, ntohs(in_service.sin_port), strerror(errno)
                  );
        SJ_RUNTIME_EXCEPTION("");
    }

    admin_socket_flags_blocking = fcntl(tmp, F_GETFL);
    admin_socket_flags_nonblocking = admin_socket_flags_blocking | O_NONBLOCK;

    if (fcntl(tmp, F_SETFL, admin_socket_flags_nonblocking) == -1)
    {
        close(tmp);
        debug.log(ALL_LEVEL, "FATAL ERROR: unable to set non blocking administration socket: %s",
                  strerror(errno)
                  );
        SJ_RUNTIME_EXCEPTION("");
    }

    admin_socket = tmp;
}

void SniffJoke::admin_socket_handle()
{
    char r_buf[MEDIUMBUF];
    uint8_t* output_buf = NULL;
    struct sockaddr_in fromaddr;

    memset(r_buf, 0x00, sizeof (r_buf));
    int fromlen = sizeof (struct sockaddr_in);
    if ((recvfrom(admin_socket, r_buf, sizeof (r_buf), 0, (sockaddr*) & fromaddr, (socklen_t *) & fromlen)) == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return;
        }
        debug.log(ALL_LEVEL, "unable to receive from local socket: %s", strerror(errno));
        SJ_RUNTIME_EXCEPTION("");
    }

    debug.log(VERBOSE_LEVEL, "received command from the client: %s", r_buf);

    output_buf = handle_cmd(r_buf);

    /* checking if the command require SniffJoke class interaction (loglevel change), these are the
     * command that could cause an interruption of the service - require to be modify the "char *output"
     * with the appropriate error - TODO ATM */
    if (debug.debuglevel != userconf.runconfig.debug_level)
    {
        debug.debuglevel = userconf.runconfig.debug_level;

        if (!debug.resetLevel())
            SJ_RUNTIME_EXCEPTION("Changing logfile settings");
    }

    /* send the answer message to the client */
    if (output_buf != NULL)
    {
        fcntl(admin_socket, F_SETFL, admin_socket_flags_blocking);
        sendto(admin_socket, output_buf, ((uint32_t *) output_buf)[0], 0, (struct sockaddr *) &fromaddr, sizeof (fromaddr));
        fcntl(admin_socket, F_SETFL, admin_socket_flags_nonblocking);
    }
    else
    {
        debug.log(ALL_LEVEL, "BUG: command handling of [%s] don't return any answer", r_buf);
    }
}

int SniffJoke::recv_command(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg)
{
    memset(databuf, 0x00, bufsize);

    int fromlen = sizeof (struct sockaddr_in), ret;

    if ((ret = recvfrom(sock, databuf, bufsize, MSG_WAITALL, from, (socklen_t *) & fromlen)) == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        debug.log(ALL_LEVEL, "unable to receive local socket: %s: %s", usermsg, strerror(errno));
    }

    return ret;
}

uint8_t* SniffJoke::handle_cmd(const char *cmd)
{
    memset(io_buf, 0x00, sizeof (io_buf));
    uint16_t* psize = (uint16_t *) io_buf;

    debug.log(DEBUG_LEVEL, "command received begin processed: [%s]", cmd);

    /* the handle_cmd_* fill partialy the io_buf, as defined
     * protocol, the first 4 byte represent the length of the
     * data, uint32_t lenght included.
     * the data returned is conform
     * to the specification in doc/SJ-PROTOCOL.txt */

    if (!memcmp(cmd, "start", strlen("start")))
    {
        handle_cmd_start();
    }
    else if (!memcmp(cmd, "stop", strlen("stop")))
    {
        handle_cmd_stop();
    }
    else if (!memcmp(cmd, "quit", strlen("quit")))
    {
        handle_cmd_quit();
    }
    else if (!memcmp(cmd, "dump", strlen("dump")))
    {
        handle_cmd_dump();
    }
    else if (!memcmp(cmd, "stat", strlen("stat")))
    {
        handle_cmd_stat();
    }
    else if (!memcmp(cmd, "info", strlen("info")))
    {
        handle_cmd_info();
    }
    else if (!memcmp(cmd, "showport", strlen("showport")))
    {
        handle_cmd_showport();
    }
    else if (!memcmp(cmd, "set", strlen("set")))
    {
        uint32_t start_port, end_port, value;
        /* Strength setValue; did Strenght be required anymore ? */

        sscanf(cmd, "set %u %u %u", &start_port, &end_port, &value);

        if (start_port < 0 || start_port > PORTNUMBER || end_port < 0 || end_port > PORTNUMBER)
            goto handle_error;

        if (start_port > end_port)
            goto handle_error;

        handle_cmd_set(start_port, end_port, value);
    }
    else if (!memcmp(cmd, "clear", strlen("clear")))
    {
        uint8_t clearPortValue = NONE;
        handle_cmd_set(0, PORTNUMBER, clearPortValue);
    }
    else if (!memcmp(cmd, "debug", strlen("debug")))
    {
        int32_t debuglevel;

        sscanf(cmd, "debug %d", &debuglevel);
        if (debuglevel < 0 || debuglevel > PACKETS_DEBUG)
            goto handle_error;

        handle_cmd_debuglevel(debuglevel);
    }
    else
    {
        debug.log(ALL_LEVEL, "Invalid command received");
    }

    debug.log(ALL_LEVEL, "handled command (%s): answer %d bytes length", cmd, *psize);
    return &io_buf[0];

handle_error:
    debug.log(ALL_LEVEL, "invalid command received");
    write_SJProtoError();

    return &io_buf[0];
}

void SniffJoke::handle_cmd_start(void)
{
    if (userconf.runconfig.active != true)
    {
        debug.log(VERBOSE_LEVEL, "%s: started sniffjoke as requested!", __func__);
    }
    else /* sniffjoke is already runconfig */
    {
        debug.log(VERBOSE_LEVEL, "%s: start requested by already running service", __func__);
    }
    userconf.runconfig.active = true;
    /* this function fill io_buf with the status information */
    write_SJStatus(START_COMMAND_TYPE);
}

void SniffJoke::handle_cmd_stop(void)
{
    if (userconf.runconfig.active != false)
    {
        debug.log(VERBOSE_LEVEL, "%s: stopped sniffjoke as requested!", __func__);
    }
    else /* sniffjoke is already runconfig */
    {
        debug.log(VERBOSE_LEVEL, "%s: stop requested by already stopped service", __func__);
    }
    userconf.runconfig.active = false;
    /* this function fill io_buf with the status information */
    write_SJStatus(STOP_COMMAND_TYPE);
}

void SniffJoke::handle_cmd_quit(void)
{
    alive = false;
    debug.log(VERBOSE_LEVEL, "%s: starting shutdown", __func__);
    write_SJStatus(QUIT_COMMAND_TYPE);
}

void SniffJoke::handle_cmd_dump(void)
{
    userconf.dump();
    /*struct command_ret retInfo;
    uint32_t dumplen = sizeof (retInfo);
    uint32_t avail = HUGEBUF - dumplen;*/

    debug.log(VERBOSE_LEVEL, "%s: configuration dumped", __func__);
    //avail -= dumpComment(io_buf, avail, "# this is a dumped file by SniffJoke version ");
    //avail -= dumpComment(io_buf, avail, SW_VERSION);
    //avail -= dumpComment(io_buf, avail, "\n");
    //avail -= dumpIfPresent(io_buff, avail, "enabler", userconf.runconfig.enabler);
    //avail -= dumpIfPresent(io_buf, avail, "chroot", userconf.runconfig.chroot_dir);

    /*retInfo.command_type = DUMP_COMMAND_TYPE;
    retInfo.len = HUGEBUF - avail;
    memcpy(&io_buf[0], &retInfo, sizeof (retInfo));*/
}

void SniffJoke::handle_cmd_stat(void)
{
    debug.log(VERBOSE_LEVEL, "%s: stat requested", __func__);
    write_SJStatus(STAT_COMMAND_TYPE);
}

void SniffJoke::handle_cmd_info(void)
{
    write_SJStatus(INFO_COMMAND_TYPE);
    debug.log(VERBOSE_LEVEL, "%s: info command NOT IMPLEMENTED", __func__);
}

void SniffJoke::handle_cmd_showport(void)
{
    write_SJPortStat(SHOWPORT_COMMAND_TYPE);
}

void SniffJoke::handle_cmd_set(uint16_t start, uint16_t end, uint8_t what)
{
    debug.log(VERBOSE_LEVEL, "%s: set TCP ports from %d to %d at %d strenght level",
              __func__, start, end, what);

    if (end == PORTNUMBER)
    {
        userconf.runconfig.portconf[PORTNUMBER - 1] = what;
        --end;
    }

    do
    {
        userconf.runconfig.portconf[start++] = what;
    }
    while (start <= end);

    write_SJPortStat(SETPORT_COMMAND_TYPE);
}

void SniffJoke::handle_cmd_debuglevel(int32_t newdebuglevel)
{
    if (newdebuglevel < ALL_LEVEL || newdebuglevel > PACKETS_DEBUG)
    {
        debug.log(ALL_LEVEL, "%s: requested debuglevel %d invalid (>= %d <= %d permitted)",
                  __func__, newdebuglevel, ALL_LEVEL, PACKETS_DEBUG
                  );
    }
    else
    {
        debug.log(ALL_LEVEL, "%s: changing log level since %d to %d\n", __func__, userconf.runconfig.debug_level, newdebuglevel);
        userconf.runconfig.debug_level = newdebuglevel;
    }
    write_SJStatus(LOGLEVEL_COMMAND_TYPE);
}

/*
 * follow the method used for compose the io_buf with the internalProtocol.h struct,
 * those methods are intetnal in UserConf, and are, exception noted for handle_cmd_dump,
 * the only commands writing in io_buf and generating answer.
 */
void SniffJoke::write_SJPortStat(uint8_t type)
{
    int i, prev_port = 1, prev_kind;
    struct command_ret retInfo;

    /* clean the buffer and fix the starting pointer */
    memset(io_buf, 0x00, HUGEBUF);
    uint8_t *p = &io_buf[sizeof (retInfo)];

    /* the first port work as initialization */
    prev_kind = userconf.runconfig.portconf[0];

    for (i = 1; i < PORTNUMBER; ++i)
    {
        if (userconf.runconfig.portconf[i] != prev_kind)
        {
            p = append_SJportBlock(p, prev_port, i - 1, prev_kind);

            prev_kind = userconf.runconfig.portconf[i];
            prev_port = i;
        }
    }

    p = append_SJportBlock(p, prev_port, PORTNUMBER, prev_kind);

    retInfo.len = p - &io_buf[0];
    retInfo.command_type = type;
    memcpy(&io_buf[0], &retInfo, sizeof (retInfo));
}

void SniffJoke::write_SJStatus(uint8_t commandReceived)
{
    struct command_ret retInfo;

    /* clean the buffer and fix the starting pointer */
    memset(io_buf, 0x00, HUGEBUF);
    uint8_t *p = &io_buf[sizeof (retInfo)];

    /* SJStatus is totally inspired by the IP/TCP options */
    p = appendSJStatus(p, STAT_ACTIVE, sizeof (userconf.runconfig.active), userconf.runconfig.active);
    p = appendSJStatus(p, STAT_MACGW, strlen(userconf.runconfig.gw_mac_str), userconf.runconfig.gw_mac_str);
    p = appendSJStatus(p, STAT_GWADDR, strlen(userconf.runconfig.gw_ip_addr), userconf.runconfig.gw_ip_addr);
    p = appendSJStatus(p, STAT_IFACE, strlen(userconf.runconfig.interface), userconf.runconfig.interface);
    p = appendSJStatus(p, STAT_LOIP, strlen(userconf.runconfig.local_ip_addr), userconf.runconfig.local_ip_addr);
    p = appendSJStatus(p, STAT_TUNN, sizeof (uint16_t), (uint16_t) userconf.runconfig.tun_number);
    p = appendSJStatus(p, STAT_DEBUGL, sizeof (userconf.runconfig.debug_level), userconf.runconfig.debug_level);
    p = appendSJStatus(p, STAT_ONLYP, strlen(userconf.runconfig.onlyplugin), userconf.runconfig.onlyplugin);
    p = appendSJStatus(p, STAT_BINDA, strlen(userconf.runconfig.admin_address), userconf.runconfig.admin_address);
    p = appendSJStatus(p, STAT_BINDP, sizeof (userconf.runconfig.admin_port), userconf.runconfig.admin_port);
    p = appendSJStatus(p, STAT_USER, strlen(userconf.runconfig.user), userconf.runconfig.user);
    p = appendSJStatus(p, STAT_GROUP, strlen(userconf.runconfig.group), userconf.runconfig.group);

    retInfo.len = (uint32_t) (p - &io_buf[0]);
    retInfo.command_type = commandReceived;
    memcpy(&io_buf[0], &retInfo, sizeof (retInfo));
}

void SniffJoke::write_SJProtoError(void)
{
    struct command_ret retInfo;
    memset(io_buf, 0x00, HUGEBUF);
    retInfo.len = sizeof (retInfo);
    retInfo.command_type = COMMAND_ERROR_MSG;
    memcpy(&io_buf[0], &retInfo, sizeof (retInfo));
}

/* follow the most "internal" method for io_buf creation, called from the methods before  */
uint8_t *SniffJoke::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, uint16_t value)
{
    *p = len + 2;
    *++p = (uint8_t) WHO;
    p++;
    memcpy(p, &value, len);

    return (p + len);
}

uint8_t *SniffJoke::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, bool value)
{
    *p = len + 2;
    *++p = (uint8_t) WHO;
    *++p = value;

    return (p + len);
}

uint8_t *SniffJoke::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, char value[MEDIUMBUF])
{
    *p = len + 2;
    *++p = (uint8_t) WHO;
    p++;
    memcpy(p, value, len);

    return (p + len);
}

uint8_t *SniffJoke::append_SJportBlock(uint8_t *p, uint16_t startP, uint16_t endP, uint8_t weight)
{
    struct port_info pInfo;

    pInfo.start = startP;
    pInfo.end = endP;
    pInfo.weight = weight;

    memcpy(p, &pInfo, sizeof (pInfo));
    return (p + sizeof (pInfo));
}
