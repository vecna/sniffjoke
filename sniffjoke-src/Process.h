#ifndef PROCESS_H
#define PROCESS_H

#define SJ_SERVICE_LOCK			 "/tmp/.sniffjoke_service.lock"
#define SJ_CLIENT_LOCK			  "/tmp/.sniffjoke_client.lock"
#define SJ_SERVICE_FATHER_PID_FILE  "/tmp/sniffjoke_father.pid"
#define SJ_SERVICE_CHILD_PID_FILE   "/tmp/sniffjoke_child.pid"
#define SJ_SERVICE_UNIXSOCK		 "sniffjoke_service" 
#define SJ_CLIENT_UNIXSOCK		  "sniffjoke_client" 

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

	Process( struct sj_useropt *useropt );
	~Process();
	pid_t readPidfile( const char *pidfile );
	void processDetach() ;
	void ReleaseLock( const char *lockpath );
	void Jail( const char *chroot_dir, struct sj_config *running );
	void PrivilegesDowngrade( struct sj_config *running );
	void CleanExit( void );
	void CleanExit( bool );
	void sigtrapSetup( sig_t sigtrap_function );
	int isServiceRunning( void );
	int isClientRunning( void );
	void writePidfile( const char *pidfile, pid_t pid );
	void SjBackground();
	void processIsolation() ;
	void SetProcType( sj_process_t ProcType );
	bool setLocktoExist( const char *lockfname );
	pid_t CheckLockExist( const char *lockfname );

};

#endif
