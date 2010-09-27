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
#ifndef SJ_PROCESS_H
#define SJ_PROCESS_H

#include "sj_defines.h"

#include <csignal>

class Process {
private:
	struct passwd *userinfo;
	struct group *groupinfo;

public:
	enum sj_process_t {
		SJ_PROCESS_UNASSIGNED = -1,
		SJ_PROCESS_SERVICE_FATHER = 0,
		SJ_PROCESS_SERVICE_CHILD = 1,
		SJ_PROCESS_CLIENT = 2
	} ProcessType;

	bool failure;
	
	sigset_t sig_nset;
	sigset_t sig_oset;
	struct sigaction action;
	struct sigaction ignore;

	Process(struct sj_useropt *useropt);
	pid_t readPidfile(const char *pidfile);
	void processDetach() ;
	void ReleaseLock(const char *lockpath);
	void Jail(const char *chroot_dir, struct sj_config *running);
	void PrivilegesDowngrade(struct sj_config *running);
	void CleanExit(void);
	void CleanExit(bool);
	void sigtrapSetup(sig_t sigtrap_function);
	void sigtrapEnable();
	void sigtrapDisable();
	int isServiceRunning(void);
	int isClientRunning(void);
	void writePidfile(const char *pidfile, pid_t pid);
	void SjBackground();
	void processIsolation() ;
	void SetProcType(sj_process_t ProcType);
	bool setLocktoExist(const char *lockfname);
	pid_t CheckLockExist(const char *lockfname);
};

#endif /* SJ_Process_H */
