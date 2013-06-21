#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "util.h"

void close_terminal(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR, 0);
	if (fd == -1) {
		perror("open /dev/null");
		return;
	}
	if(dup2(fd, STDIN_FILENO) < 0) {
		perror("dup2 stdin");
		return;
	}
	if(dup2(fd, STDOUT_FILENO) < 0) {
		perror("dup2 stdout");
		return;
	}
	if(dup2(fd, STDERR_FILENO) < 0) {
		perror("dup2 stderr");
		return;
	}
	if (fd > STDERR_FILENO && close(fd) < 0) {
		perror("close");
		return;
	}
}

void insert_kmod(const char *mod)
{
	pid_t pid;

	pid = fork();
	assert(pid != -1);

	if (pid > 0) {
		int stat;
		pid_t c;

		while ((c = waitpid(pid, &stat, 0)) == (pid_t)-1 && errno == EINTR);
		assert(c == pid);
		assert(stat == 0);
	} else {
		char *argv[5];

		argv[0] = "/sbin/insmod";
		argv[1] = (char *)mod;
		argv[2] = NULL;
		
		assert(execv(argv[0], argv) == 0);
	}
}

int check_kmod(const char *mod)
{
	int fd, size = 0, ret = 0;
	char *buf = NULL;

	if ((fd = open("/proc/modules", O_RDONLY, 0)) == -1) {
		perror("open /proc/modules");
		ret = -1;
		goto out;
	}
retry:
	size += 1000;
	if (!(buf = (char *)realloc(buf, size))) {
		perror("malloc");
		ret = -1;
		goto close;
	}
	ret = read(fd, buf + size - 1000, 1000); 
	if (ret == -1) {
		perror("read");
		goto free;
	} else if (ret == 1000) {
		goto retry;
	}
	if (strstr(buf, mod)) {
		ret = 1;
	} else {
		ret = 0;
	}

free:
	free(buf);
close:
	close(fd);
out:
	return ret;
}

void remove_kmod(const char *mod)
{
	pid_t pid;

	pid = fork();
	assert(pid != -1);

	if (pid > 0) {
		int stat;
		pid_t c;

		while ((c = waitpid(pid, &stat, 0)) == (pid_t)-1 && errno == EINTR);
		assert(c == pid);
		assert(stat == 0);
	} else {
		char *argv[5];

		argv[0] = "/sbin/rmmod";
		argv[1] = (char *)mod;
		argv[2] = NULL;

		assert(execv(argv[0], argv) == 0);
	}
}

void __start_kmc_server(char *argv[])
{
	pid_t pid;

	pid = fork();
	assert(pid != -1);

	if (pid > 0) {
		int stat;
		pid_t c;

		while ((c = waitpid(pid, &stat, 0)) == (pid_t)-1 && errno == EINTR);
		assert(c == pid);
		assert(stat == 0);
	} else {
		assert(execv(argv[0], argv) == 0);
	}
}

void __stop_kmc_server(char *argv[])
{
	pid_t pid;

	pid = fork();
	assert(pid != -1);

	if (pid > 0) {
		int stat;
		pid_t c;

		while ((c = waitpid(pid, &stat, 0)) == (pid_t)-1 && errno == EINTR);
		assert(c == pid);
		assert(stat == 0);
	} else {
		char *argv[5];

		argv[0] = "/sbin/rmmod";
		argv[1] = "kmemcache";
		argv[2] = NULL;

		assert(execv(argv[0], argv) == 0);
	}
}

void start_kmc_server(char *argv[])
{
	int status;

	status = check_kmod("kmemcache");
retry:
	switch (status) {
	case 0:
		insert_kmod(argv[0]);
		__start_kmc_server(argv + 1);
		break;
	case -1:
	default:
		perror("start_kmc_server");
		break;
	case 1:
		__stop_kmc_server(NULL);
		status = 0;
		goto retry;
	}
}

void stop_kmc_server(char *argv[])
{
	int status;

	status = check_kmod("kmemcache");
	switch (status) {
	case 1:
		__stop_kmc_server(argv);
		break;
	case -1:
	default:
		perror("stop_kmc_server");
	case 0:
		break;
	}
}
