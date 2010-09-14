#ifndef PROCESS_H
#define PROCESS_H

#include "defines.h"

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

	Process(struct sj_useropt *useropt);
	~Process();
	pid_t readPidfile(const char *pidfile);
	void processDetach() ;
	void ReleaseLock(const char *lockpath);
	void Jail(const char *chroot_dir, struct sj_config *running);
	void PrivilegesDowngrade(struct sj_config *running);
	void CleanExit(void);
	void CleanExit(bool);
	void sigtrapSetup(sig_t sigtrap_function);
	int isServiceRunning(void);
	int isClientRunning(void);
	void writePidfile(const char *pidfile, pid_t pid);
	void SjBackground();
	void processIsolation() ;
	void SetProcType(sj_process_t ProcType);
	bool setLocktoExist(const char *lockfname);
	pid_t CheckLockExist(const char *lockfname);
};

#endif
