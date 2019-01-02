#ifndef LOAD_TRACER_H
#define LOAD_TRACER_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#include "utils/utils.h"

#define LOADTRACER_REQUEST_MAGIC 0x3AAA
#define LOADTRACER_REPLY_MAGIC 0x4AAA
#define LIBLOADER_SOCKET_DIR "/tmp/libloader"

enum libloader_request_type {
	LIBLODAER_SET_ENV,
	LIBLOADER_DL_OPEN,
	LIBLOADER_DL_CLOSE,
	LIBLOADER_START_TRACING,
	LIBLOADER_STOP_TRACING,
};

enum libloader_reply_type {
	LIBLODAER_SUCESS,
	LIBLOADER_FAILURE,
};

struct libloader_reply {
	unsigned short magic;
	unsigned short type;
};

struct libloader_request {
	unsigned short magic;
	unsigned short type;
	unsigned int len;
	unsigned char data[];
};

struct libloader_request_env {
	unsigned int len;
	unsigned char value[];
};

struct libloader_request_dlopen {
	int  namelen;
	int flags;	
	char libname[];
};

struct libloader_request_dlclose {
	int  namelen;	
	char libname[];
};

struct libloader_request_start_tracing {
	int  namelen;
	char libname[];
};

struct libloader_request_stop_tracing {
	int  namelen;
	char libname[];
};

enum libloader_request_type recv_reply(int sock)
{
	struct libloader_reply reply;

	if (read_all(sock, &reply, sizeof(reply)) < 0)
		return LIBLOADER_FAILURE;

	if (reply.magic != LOADTRACER_REPLY_MAGIC)
		return LIBLOADER_FAILURE;

	return reply.type;
}

/* libloader API */
enum libloader_request_type send_start_tracing_request(int sock, const char* name)
{
	struct libloader_request_start_tracing request_start_tracing = {
		.namelen = strlen(name),
	};
	struct libloader_request request = {
		.magic = LOADTRACER_REQUEST_MAGIC,
		.type = LIBLOADER_START_TRACING,
		.len = sizeof(request_start_tracing) + strlen(name),
	};
	struct iovec iov[3] = {
		{ .iov_base = &request, .iov_len = sizeof(request), },
		{ .iov_base = &request_start_tracing, .iov_len = sizeof(request_start_tracing), },
		{ .iov_base = (void *) name, .iov_len = request_start_tracing.namelen, },
	};
	int len = sizeof(request) + request.len;

	if (sock < 0)
		return LIBLOADER_FAILURE;

	if (writev(sock, iov, 3) != len) {
		/* TODO normal stop */
		/*if (!mcount_should_stop())
			pr_err("write tid info failed");*/
		printf("send_start_tracing_request couldnt write all bytes\n");
	}

	return recv_reply(sock);
}

enum libloader_request_type send_stop_tracing_request(int sock, const char* name)
{
	struct libloader_request_stop_tracing request_stop_tracing = {
		.namelen = strlen(name),
	};
	struct libloader_request request = {
		.magic = LOADTRACER_REQUEST_MAGIC,
		.type = LIBLOADER_STOP_TRACING,
		.len = sizeof(request_stop_tracing) + strlen(name),
	};
	struct iovec iov[3] = {
		{ .iov_base = &request, .iov_len = sizeof(request), },
		{ .iov_base = &request_stop_tracing, .iov_len = sizeof(request_stop_tracing), },
		{ .iov_base = (void *) name, .iov_len = request_stop_tracing.namelen, },
	};
	int len = sizeof(request) + request.len;

	if (sock < 0)
		return LIBLOADER_FAILURE;

	if (writev(sock, iov, 3) != len) {
		printf("send_stop_tracing_request couldnt write all bytes\n");
	}

	return recv_reply(sock);
}

enum libloader_request_type send_env_request(int sock, const char* name, const char* value)
{
	struct libloader_request_env request_env_name = {
		.len = strlen(name),
	};
	struct libloader_request_env request_env_value = {
		.len = strlen(value),
	};
	struct libloader_request request = {
		.magic = LOADTRACER_REQUEST_MAGIC,
		.type = LIBLODAER_SET_ENV,
		.len = sizeof(request_env_name) + strlen(name) + sizeof(request_env_value) + strlen(value),
	};
	struct iovec iov[5] = {
		{ .iov_base = &request, .iov_len = sizeof(request), },
		{ .iov_base = &request_env_name, .iov_len = sizeof(request_env_name), },
		{ .iov_base = (void *) name, .iov_len = request_env_name.len, },
		{ .iov_base = &request_env_value, .iov_len = sizeof(request_env_value), },
		{ .iov_base = (void *) value, .iov_len = request_env_value.len, },
	};
	int len = sizeof(request) + request.len;

	if (sock < 0)
		return LIBLOADER_FAILURE;

	if (writev(sock, iov, 5) != len) {
		printf("send_env_request couldnt write all bytes\n");
	}

	return recv_reply(sock);
}

enum libloader_request_type send_dlopen_request(int sock, const char* name, int flags)
{
	struct libloader_request_dlopen request_dlopen = {
		.namelen = strlen(name),
		.flags = flags,
	};
	struct libloader_request request = {
		.magic = LOADTRACER_REQUEST_MAGIC,
		.type = LIBLOADER_DL_OPEN,
		.len = sizeof(request_dlopen) + strlen(name) ,
	};
	struct iovec iov[3] = {
		{ .iov_base = &request, .iov_len = sizeof(request), },
		{ .iov_base = &request_dlopen, .iov_len = sizeof(request_dlopen), },
		{ .iov_base = (void *) name, .iov_len = request_dlopen.namelen, },
	};
	int len = sizeof(request) + request.len;

	if (sock < 0)
		return LIBLOADER_FAILURE;

	if (writev(sock, iov, 3) != len) {
		printf("send_dlopen_request couldnt write all bytes\n");
	}

	return recv_reply(sock);
}

enum libloader_request_type send_dlclose_request(int sock, const char* name)
{
	struct libloader_request_dlclose request_dlclose = {
		.namelen = strlen(name),
	};
	struct libloader_request request = {
		.magic = LOADTRACER_REQUEST_MAGIC,
		.type = LIBLOADER_DL_CLOSE,
		.len = sizeof(request_dlclose) + strlen(name),
	};
	struct iovec iov[3] = {
		{ .iov_base = &request, .iov_len = sizeof(request), },
		{ .iov_base = &request_dlclose, .iov_len = sizeof(request_dlclose), },
		{ .iov_base = (void *) name, .iov_len = request_dlclose.namelen, },
	};
	int len = sizeof(request) + request.len;

	if (sock < 0)
		return LIBLOADER_FAILURE;

	if (writev(sock, iov, 3) != len) {
		printf("send_dlclose_request couldnt write all bytes\n");
	}

	return recv_reply(sock);
}

#endif /* LOAD_TRACER_H */