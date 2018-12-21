#ifndef LOAD_TRACER_H
#define LOAD_TRACER_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#define LOADTRACER_CMD_MAGIC 0x3AAA
#define LIBLOADER_SOCKET_DIR "/tmp/libloader"

enum libloader_cmd_type {
	LIBLODAER_SET_ENV,
	LIBLOADER_DL_OPEN,
	LIBLOADER_DL_CLOSE,
	LIBLOADER_START_TRACING,
	LIBLOADER_STOP_TRACING,
};

struct libloader_cmd {
	unsigned short magic;
	unsigned short type;
	unsigned int len;
	unsigned char data[];
};

struct libloader_cmd_env {
	unsigned int len;
	unsigned char value[];
};

struct libloader_cmd_dlopen {
	int  namelen;
	int flags;	
	char libname[];
};

struct libloader_cmd_dlclose {
	int  namelen;	
	char libname[];
};

struct libloader_cmd_start_tracing {
	int  namelen;
	char libname[];
};

struct libloader_cmd_stop_tracing {
	int  namelen;
	char libname[];
};

/* libloader API */
void send_start_tracing_cmd(int sock, const char* name)
{
	struct libloader_cmd_start_tracing cmd_start_tracing = {
		.namelen = strlen(name),
	};
	struct libloader_cmd cmd = {
		.magic = LOADTRACER_CMD_MAGIC,
		.type = LIBLOADER_START_TRACING,
		.len = sizeof(cmd_start_tracing) + strlen(name),
	};
	struct iovec iov[3] = {
		{ .iov_base = &cmd, .iov_len = sizeof(cmd), },
		{ .iov_base = &cmd_start_tracing, .iov_len = sizeof(cmd_start_tracing), },
		{ .iov_base = (void *) name, .iov_len = cmd_start_tracing.namelen, },
	};
	int len = sizeof(cmd) + cmd.len;

	if (sock < 0)
		return;

	if (writev(sock, iov, 3) != len) {
		/* TODO normal stop */
		/*if (!mcount_should_stop())
			pr_err("write tid info failed");*/
		printf("couldnt write all bytes\n");
	}
}
void send_stop_tracing_cmd(int sock, const char* name)
{
	struct libloader_cmd_stop_tracing cmd_stop_tracing = {
		.namelen = strlen(name),
	};
	struct libloader_cmd cmd = {
		.magic = LOADTRACER_CMD_MAGIC,
		.type = LIBLOADER_STOP_TRACING,
		.len = sizeof(cmd_stop_tracing) + strlen(name),
	};
	struct iovec iov[3] = {
		{ .iov_base = &cmd, .iov_len = sizeof(cmd), },
		{ .iov_base = &cmd_stop_tracing, .iov_len = sizeof(cmd_stop_tracing), },
		{ .iov_base = (void *) name, .iov_len = cmd_stop_tracing.namelen, },
	};
	int len = sizeof(cmd) + cmd.len;

	if (sock < 0)
		return;

	if (writev(sock, iov, 3) != len) {
		printf("couldnt write all bytes\n");
	}
}
void send_env_cmd(int sock, const char* name, const char* value)
{
	struct libloader_cmd_env cmd_env_name = {
		.len = strlen(name),
	};
	struct libloader_cmd_env cmd_env_value = {
		.len = strlen(value),
	};
	struct libloader_cmd cmd = {
		.magic = LOADTRACER_CMD_MAGIC,
		.type = LIBLODAER_SET_ENV,
		.len = sizeof(cmd_env_name) + strlen(name) + sizeof(cmd_env_value) + strlen(value),
	};
	struct iovec iov[5] = {
		{ .iov_base = &cmd, .iov_len = sizeof(cmd), },
		{ .iov_base = &cmd_env_name, .iov_len = sizeof(cmd_env_name), },
		{ .iov_base = (void *) name, .iov_len = cmd_env_name.len, },
		{ .iov_base = &cmd_env_value, .iov_len = sizeof(cmd_env_value), },
		{ .iov_base = (void *) value, .iov_len = cmd_env_value.len, },
	};
	int len = sizeof(cmd) + cmd.len;

	if (sock < 0)
		return;

	if (writev(sock, iov, 5) != len) {
		printf("couldnt write all bytes\n");
	}
}
void send_dlopen_cmd(int sock, const char* name, int flags)
{
	struct libloader_cmd_dlopen cmd_dlopen = {
		.namelen = strlen(name),
		.flags = flags,
	};
	struct libloader_cmd cmd = {
		.magic = LOADTRACER_CMD_MAGIC,
		.type = LIBLOADER_DL_OPEN,
		.len = sizeof(cmd_dlopen) + strlen(name) ,
	};
	struct iovec iov[3] = {
		{ .iov_base = &cmd, .iov_len = sizeof(cmd), },
		{ .iov_base = &cmd_dlopen, .iov_len = sizeof(cmd_dlopen), },
		{ .iov_base = (void *) name, .iov_len = cmd_dlopen.namelen, },
	};
	int len = sizeof(cmd) + cmd.len;

	if (sock < 0)
		return;

	if (writev(sock, iov, 3) != len) {
		printf("couldnt write all bytes\n");
	}
}
void send_dlclose_cmd(int sock, const char* name)
{
	struct libloader_cmd_dlclose cmd_dlclose = {
		.namelen = strlen(name),
	};
	struct libloader_cmd cmd = {
		.magic = LOADTRACER_CMD_MAGIC,
		.type = LIBLOADER_DL_CLOSE,
		.len = sizeof(cmd_dlclose) + strlen(name),
	};
	struct iovec iov[3] = {
		{ .iov_base = &cmd, .iov_len = sizeof(cmd), },
		{ .iov_base = &cmd_dlclose, .iov_len = sizeof(cmd_dlclose), },
		{ .iov_base = (void *) name, .iov_len = cmd_dlclose.namelen, },
	};
	int len = sizeof(cmd) + cmd.len;

	if (sock < 0)
		return;

	if (writev(sock, iov, 3) != len) {
		printf("couldnt write all bytes\n");
	}
}

#endif /* LOAD_TRACER_H */