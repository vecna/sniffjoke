/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
    
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

#include "Process.h"
#include "UserConf.h"

#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>

/* startup of the process */
Process::Process(const struct sj_config &runcfg) :
runconfig(runcfg),
userinfo_buf(NULL),
groupinfo_buf(NULL)
{
    LOG_DEBUG("");

    if (getuid() || geteuid())
        RUNTIME_EXCEPTION("required root privileges");

    struct passwd *userinfo_result;
    struct group *groupinfo_result;

    size_t userinfo_buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t groupinfo_buf_len = sysconf(_SC_GETGR_R_SIZE_MAX);

    userinfo_buf = calloc(1, userinfo_buf_len);
    groupinfo_buf = calloc(1, groupinfo_buf_len);

    if (userinfo_buf == NULL || groupinfo_buf == NULL)
        RUNTIME_EXCEPTION("problem during memory allocation for userinfo or groupinfo");

    getpwnam_r(runconfig.user, &userinfo, (char*) userinfo_buf, userinfo_buf_len, &userinfo_result);
    getgrnam_r(runconfig.group, &groupinfo, (char*) groupinfo_buf, groupinfo_buf_len, &groupinfo_result);

    if (userinfo_result == NULL || groupinfo_result == NULL)
        RUNTIME_EXCEPTION("invalid user or group specified: %s, %s", runconfig.user, runconfig.group);
}

Process::~Process(void)
{
    LOG_DEBUG("[process id %d, uid %d]", getpid(), getuid());

    free(userinfo_buf);
    free(groupinfo_buf);
}

int Process::detach(void)
{
    pid_t pid_child;
    int pdes[2];
    pipe(pdes);

    if ((pid_child = fork()) == -1)
        RUNTIME_EXCEPTION("unable to fork (calling pid %d, parent %d)", getpid(), getppid());

    if (pid_child)
    {
        /*
         * Sniffjoke SERVICE FATHER: root privileges
         * process delegated to network cleanhup
         */

        close(pdes[1]);
        read(pdes[0], &pid_child, sizeof (pid_t));
        close(pdes[0]);

        return pid_child;

    }
    else
    {
        /*
         * Sniffjoke SERVICE CHILD: I/O, user privileges
         * networking process
         */

        pid_child = getpid();

        close(pdes[0]);
        write(pdes[1], &pid_child, sizeof (pid_t));
        close(pdes[1]);

        LOG_DEBUG("forked child process, pid %d", getpid());

        return 0;
    }
}

void Process::jail(const char *chroot_dir)
{
    mkdir(chroot_dir, 0700);

    if (chown(chroot_dir, userinfo.pw_uid, groupinfo.gr_gid))
    {
        RUNTIME_EXCEPTION("chown of %s to %s:%s failed: %s: unable to start SniffJoke",
                          chroot_dir, runconfig.user, runconfig.group, strerror(errno));
    }

    if (chdir(chroot_dir) || chroot(chroot_dir))
        RUNTIME_EXCEPTION("chroot into %s: %s: unable to start sniffjoke",
                          chroot_dir, strerror(errno));

    LOG_VERBOSE("chroot'ed process %d in %s", getpid(), chroot_dir);
}

void Process::privilegesDowngrade(void)
{
    debug.downgradeOpenlog(userinfo.pw_uid, groupinfo.gr_gid);

    if (setgid(groupinfo.gr_gid) || setuid(userinfo.pw_uid))
        RUNTIME_EXCEPTION("error loosing root privileges");

    if (!getuid() && !geteuid())
        RUNTIME_EXCEPTION("SniffJoke user process can't be runned with root privileges");

    LOG_VERBOSE("process %d downgrade privileges to uid %d gid %d",
                getpid(), userinfo.pw_uid, groupinfo.gr_gid);
}

void Process::sigtrapSetup(sig_t sigtrap_function)
{
    struct sigaction ignore;
    memset(&ignore, 0, sizeof (struct sigaction));

    sigemptyset(&sig_nset);
    sigaddset(&sig_nset, SIGINT);
    sigaddset(&sig_nset, SIGABRT);
    sigaddset(&sig_nset, SIGTERM);
    sigaddset(&sig_nset, SIGQUIT);
    sigaddset(&sig_nset, SIGCHLD);

    memset(&action, 0, sizeof (struct sigaction));
    action.sa_handler = sigtrap_function;
    action.sa_mask = sig_nset;

    ignore.sa_handler = SIG_IGN;

    sigaction(SIGINT, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGUSR1, &ignore, NULL);
}

void Process::sigtrapEnable(void)
{
    sigprocmask(SIG_SETMASK, &sig_oset, NULL);
}

void Process::sigtrapDisable(void)
{
    sigemptyset(&sig_nset);
    sigaddset(&sig_nset, SIGINT);
    sigaddset(&sig_nset, SIGABRT);
    sigaddset(&sig_nset, SIGTERM);
    sigaddset(&sig_nset, SIGQUIT);
    sigprocmask(SIG_BLOCK, &sig_nset, &sig_oset);
}

pid_t Process::readPidfile(void)
{
    int ret = 0;

    FILE *pidFile = fopen(SJ_PIDFILE, "r");
    if (pidFile == NULL)
    {
        LOG_DEBUG("pidfile %s not present: %s", SJ_PIDFILE, strerror(errno));
        return ret;
    }

    char tmpstr[10];
    if (fgets(tmpstr, 100, pidFile) != NULL)
        ret = atoi(tmpstr);
    fclose(pidFile);


    return ret;
}

void Process::writePidfile(void)
{
    FILE *pidFile = fopen(SJ_PIDFILE, "w");
    if (pidFile == NULL)
        RUNTIME_EXCEPTION("unable to open pidfile %s for pid %d for writing", SJ_PIDFILE, getpid());

    LOG_DEBUG("created pidfile %s from %d", SJ_PIDFILE, getpid());

    fprintf(pidFile, "%d", getpid());
    fclose(pidFile);
}

/* pidfile will be deleted if personal or derived from another process, the argument mean this */
void Process::unlinkPidfile(bool killOther)
{
    FILE *pidFile = fopen(SJ_PIDFILE, "r");
    char line[SMALLBUF];
    pid_t written;

    if (pidFile == NULL)
    {
        LOG_DEBUG("error with file %s: %s", SJ_PIDFILE, strerror(errno));
        return;
    }

    fgets(line, SMALLBUF, pidFile);
    written = atoi(line);
    fclose(pidFile);

    if (!written)
    {
        LOG_DEBUG("unable to read of %s", SJ_PIDFILE);
        goto __unlinkPidfile;
    }

    if (written != getpid() && killOther)
    {
        LOG_DEBUG("ready to delete %s with %d pid (we are %d)", SJ_PIDFILE, written, getpid());
        goto __unlinkPidfile;
    }

    if (written != getpid())
    {
        LOG_DEBUG("ignored request (written %d we %d)", written, getpid());
        return;
    }

__unlinkPidfile:

    if (unlink(SJ_PIDFILE))
        RUNTIME_EXCEPTION("weird, I'm able to open but not to unlink %s: %s", SJ_PIDFILE, strerror(errno));

    LOG_DEBUG("pid %d unlinked pidfile %s", getpid(), SJ_PIDFILE);
}

void Process::background(void)
{
    if (fork())
        exit(0);

    int i;
    for (i = getdtablesize(); i >= 0; --i)
        close(i);

    i = open("/dev/null", O_RDWR); /* stdin  */
    dup(i); /* stdout */
    dup(i); /* stderr */
}

void Process::isolation(void)
{
    LOG_DEBUG("the pid %d, uid %d is isolating themeself", getpid(), getuid());

    setsid();
    umask(027);
}

/* Are you happy, gcc ? Process.cc:280:2: warning: no newline at end of file */

