#ifndef LOAD_TRACER_H
#define LOAD_TRACER_H

#include <pthread.h>
#include <stdint.h>


#define LOADTRACER_MSG_MAGIC 0x3AAA
#define SOCKET_DIR "/tmp/loadtracer"

enum libloader_msg_type {
	LIBLODAER_SET_ENV,
	LIBLOADER_DL_OPEN,
	LIBLOADER_DL_CLOSE,
};

struct libloader_msg {
	unsigned short magic;
	unsigned short type;
	unsigned int len;
	unsigned char data[];
};

struct libloader_msg_env {
	unsigned int len;
	unsigned char value[];
};

/*struct uftrace_msg_sess {
	char sid[16];
	int  unused;
	int  namelen;
	char exename[];
};*/

struct libloader_msg_dlopen {
	int  namelen;
	int flags;	
	char exename[];
};

#endif /* LOAD_TRACER_H */