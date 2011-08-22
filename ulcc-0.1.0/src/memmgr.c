/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 *
 * Thanks to Richard Stevens. Some daemon initialization routines are borrowed
 * from the book `Advanced Programming in the Unix Environment'.
 */

#include <sys/resource.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "memmgr.h"
#include "mmsvr.h"

#define LOCKFILE "/var/run/ulccmmd.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

int lockfile(int fd)
{
	struct flock	fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	return(fcntl(fd, F_SETLK, &fl));
}

int already_running(void)
{
	int		fd;
	char	buf[32];

	fd = open(LOCKFILE, O_RDWR|O_CREAT, LOCKMODE);
	if(fd < 0)
	{
		syslog(LOG_ERR, "cannot open %s: %m", LOCKFILE);
		exit(1);
	}

	if(lockfile(fd) < 0)
	{
		if(errno == EACCES || errno == EAGAIN)
		{
			close(fd);
			return(1);
		}
		syslog(LOG_ERR, "cannot lock %s: %m", LOCKFILE);
		exit(1);
	}

	if(ftruncate(fd, 0) < 0)
	{
		syslog(LOG_WARNING, "cannont truncate the lock file to zero: %m");
	}
	sprintf(buf, "%ld", (long)getpid());
	if(write(fd, buf, strlen(buf) + 1) < 0)
	{
		syslog(LOG_WARNING, "cannot write process id into the lock file: %m");
	}

	return 0;
}

void daemonize(const char *cmd)
{
	int					i, fd0, fd1, fd2;
	pid_t				pid;
	struct rlimit		rl;
	struct sigaction	sa;

	/* Clear file creation mask.
	 */
	umask(0);

	/* Get maximum number of file descriptors.
	 */
	if(getrlimit(RLIMIT_NOFILE, &rl) < 0)
	{
		perror("cannot get file limit");
		exit(1);
	}

	/* Become a session leader to lose controlling TTY.
	 */
	if((pid = fork()) < 0)
	{
		perror("cannot fork to become session leader");
		exit(1);
	}
	else if(pid != 0) /* parent */
	{
		exit(0);
	}
	setsid();

	/* Ensure future opens won't allocate controlling TTYs.
	 */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if(sigaction(SIGHUP, &sa, NULL) < 0)
	{
		perror("cannot ignore SIGHUP");
		exit(1);
	}
	if((pid = fork()) < 0)
	{
		perror("cannot fork to ignore SIGHUP");
		exit(1);
	}
	else if(pid != 0) /* parent */
	{
		exit(0);
	}

	/* Change the current working directory to the root so
	 * we won't prevent file systems from being unmounted.
	 */
	if(chdir("/") < 0)
	{
		perror("cannot change directory to /");
		exit(1);
	}

	/* Close all open file descriptors.
	 */
	if(rl.rlim_max == RLIM_INFINITY)
	{
		rl.rlim_max = 1024;
	}
	for(i = 0; i < rl.rlim_max; i++)
	{
		close(i);
	}

	/* Attach file descriptors 0, 1, and 2 to /dev/null.
	 */
	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	/* Initialize the log file.
	 */
	openlog(cmd, LOG_CONS, LOG_USER);
	if(fd0 != 0 || fd1 != 1 || fd2 != 2)
	{
		syslog(LOG_ERR, "unexpected file descriptors %d %d %d", fd0, fd1, fd2);
		exit(1);
	}
}

extern int mm_cont;
extern mqd_t svcque;
extern mqd_t ctlque;

void mmsvr_sigterm(int signo)
{
	mm_cont = 0;
	mq_close(svcque);
	mq_close(ctlque);
}

int ignore_oom()
{
	char	buf[64];
	sprintf(buf, "echo -17 > /proc/%d/oom_adj", getpid());
	return system(buf);
}

int main(int argc, char *argv[])
{
	char				*cmd;
	struct sigaction	sa;

	if((cmd = strrchr(argv[0], '/')) == NULL)
	{
		cmd = argv[0];
	}
	else
	{
		cmd++;
	}

	/* Parse arguments.
	 */
	if(parse_args(argc, argv) < 0)
	{
		exit(0);
	}

	/* Become a daemon.
	 */
	daemonize(cmd);

	/* Make sure only one copy of the daemon is running.
	 */
	if(already_running())
	{
		syslog(LOG_ERR, "memory manager daemon already running");
		exit(1);
	}

	/* Handle signals of interest.
	 */
	sa.sa_handler = mmsvr_sigterm;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sa.sa_flags = 0;
	if(sigaction(SIGTERM, &sa, NULL) < 0)
	{
		syslog(LOG_ERR, "can't catch SIGTERM: %m");
		exit(1);
	}

	/* Prevent this daemon from being killed by OOM.
	 */
	if(ignore_oom() < 0)
	{
		syslog(LOG_ERR, "memory manager at risk of being killed by oom");
	}

	/* Initialize memory manager environment.
	 */
	if(mm_init() < 0)
	{
		syslog(LOG_EMERG, "memory manager init failed");
		exit(1);
	}

	/* Launch the service.
	 */
	mm_go();

	/* Clean up before exit.
	 */
	mm_fini();

	syslog(LOG_INFO, "memory manager exited");
	exit(0);
}
