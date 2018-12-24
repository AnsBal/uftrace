#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <dlfcn.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "libloader"
#define PR_DOMAIN  DBG_LIBLOADER

#include "libloader.h"
#include "utils/utils.h"

static int libloader_sock;
static int libloader_efd;

static void epoll_add(int efd, int fd, unsigned event)
{
	struct epoll_event ev = {
		.events	= event,
		.data	= {
			.fd = fd,
		},
	};

	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0)
		pr_err("epoll add failed");
}

static void recv_start_tracing_cmd(int sock, int len)
{
	void *buffer;
	struct libloader_cmd_start_tracing cmd_start_tracing;
	unsigned int cmd_env_len;
	char* libname;

	if (len < sizeof(cmd_start_tracing))
			pr_err_ns("invalid message length\n");

	if (read_all(sock, &cmd_start_tracing, sizeof(cmd_start_tracing)) < 0)
		pr_err("recv cmd_start_tracing failed");

	libname = xmalloc(cmd_start_tracing.namelen + 1);
	if (read_all(sock, libname, cmd_start_tracing.namelen) < 0)
		pr_err("recv cmd_start_tracing failed");
	libname[cmd_start_tracing.namelen] = '\0';
	
	void* handle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
	if (!handle) {
		pr_err("start tracing failed");
	}
	
	void (*start_tracing)(void);
	start_tracing = dlsym(handle, "start_tracing");
	if (!start_tracing) {
		pr_err("start tracing request failed");		
	}

	pr_dbg2("cmd TRACEON: %s\n", libname);

	start_tracing();
	free(libname);
}

static void recv_stop_tracing_cmd(int sock, int len)
{
	void *buffer;
	struct libloader_cmd_stop_tracing cmd_stop_tracing;
	unsigned int cmd_env_len;
	char* libname;

	if (len < sizeof(cmd_stop_tracing))
			pr_err_ns("invalid message length\n");

	if (read_all(sock, &cmd_stop_tracing, sizeof(cmd_stop_tracing)) < 0)
		pr_err("recv cmd_stop_tracing failed");

	libname = xmalloc(cmd_stop_tracing.namelen + 1);
	if (read_all(sock, libname, cmd_stop_tracing.namelen) < 0)
		pr_err("recv cmd_stop_tracing failed");
	libname[cmd_stop_tracing.namelen] = '\0';
	
	void* handle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
	if (!handle) {
		pr_err("dlclose request failed");
	}
	
	void (*stop_tracing)(void);
	stop_tracing = dlsym(handle, "stop_tracing");
	if (!stop_tracing) {
		pr_err("stop tracing request failed");		
	}

	pr_dbg2("cmd TRACEOFF: %s\n", libname);

	stop_tracing();
	free(libname);
}

static void recv_dlclose_cmd(int sock, int len)
{
	void *buffer;
	struct libloader_cmd_dlclose cmd_dlclose;
	unsigned int cmd_env_len;
	char* libname;

	if (len < sizeof(cmd_dlclose))
			pr_err_ns("invalid message length\n");

	if (read_all(sock, &cmd_dlclose, sizeof(cmd_dlclose)) < 0)
		pr_err("recv cmd_dlclose failed");

	libname = xmalloc(cmd_dlclose.namelen + 1);
	if (read_all(sock, libname, cmd_dlclose.namelen) < 0)
		pr_err("recv cmd_dlclose failed");
	libname[cmd_dlclose.namelen] = '\0';
	
	void* handle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
	if (!handle) {
		pr_err("dlclose request failed");
	}

	if (dlclose(handle)) {
		pr_err("dlclose request failed");
	} printf("handle %p \n", handle); fflush(stdout);
		
	if (dlclose(handle)) {
		pr_err("dlclose request failed");
	}	printf("handle %p \n", handle); fflush(stdout);
	if (dlclose(handle)) {
		pr_err("dlclose request failed");
	}printf("handle %p \n", handle); fflush(stdout);
	if (dlclose(handle)) {
		//pr_err("dlclose request failed");
	} exit(0);
	
	pr_dbg2("cmd DLCLOSE: %s: %p\n", libname, handle);

	free(libname);
}

static void recv_dlopen_cmd(int sock, int len)
{
	void *buffer;
	struct libloader_cmd_dlopen cmd_dlopen;
	unsigned int cmd_env_len;
	char* libname;

	if (len < sizeof(cmd_dlopen))
			pr_err_ns("invalid message length\n");

	if (read_all(sock, &cmd_dlopen, sizeof(cmd_dlopen)) < 0)
		pr_err("recv cmd_env failed");

	libname = xmalloc(cmd_dlopen.namelen + 1);
	if (read_all(sock, libname, cmd_dlopen.namelen) < 0)
		pr_err("recv cmd_env failed");
	libname[cmd_dlopen.namelen] = '\0';

	void* handle = dlopen(libname, cmd_dlopen.flags);
	if (!handle) {
		pr_err("dlopen request failed");
	}
	
	pr_dbg2("cmd DLOPEN: %s\n", libname);

	free(libname);
}

static void recv_env_cmd(int sock, int len)
{
	void *buffer;
	struct libloader_cmd_env cmd_env;
	unsigned int cmd_env_len;
	char* varname;
	char* value;

	if (len < sizeof(cmd_env))
			pr_err_ns("invalid message length\n");

	if (read_all(sock, &cmd_env, sizeof(cmd_env)) < 0)
		pr_err("recv cmd_env failed");

	varname = xmalloc(cmd_env.len + 1);
	if (read_all(sock, varname, cmd_env.len) < 0)
		pr_err("recv cmd_env failed");
	varname[cmd_env.len] = '\0';

	if (read_all(sock, &cmd_env, sizeof(cmd_env)) < 0)
		pr_err("recv cmd_env failed");

	value = xmalloc(cmd_env.len + 1);
	if (read_all(sock, value, cmd_env.len) < 0)
		pr_err("recv cmd_env failed");
	value[cmd_env.len] = '\0';

	if(setenv(varname, value, 1) == -1)
		pr_err("setenv request failed");

	pr_dbg3("cmd SETENV: %s: %s \n", varname, value);

	free(varname);
	free(value);
}

static void handle_server_sock(struct epoll_event *ev, int efd)
{
	int client;
	int sock = ev->data.fd;

	client = accept(sock, NULL, NULL);
	if (client < 0)
		pr_err("socket accept failed");

	epoll_add(efd, client, EPOLLIN);
}

static void handle_libloader_cmd(struct epoll_event *ev, int efd)
{
	int sock = ev->data.fd;
	struct libloader_cmd cmd;

	if (ev->events & (EPOLLERR | EPOLLHUP)) {
		pr_dbg("client socket closed\n");
		
		if (epoll_ctl(efd, EPOLL_CTL_DEL, sock, NULL) < 0)
			pr_err("epoll del failed");

		close(sock);
		return;
	}

	if (read_all(sock, &cmd, sizeof(cmd)) < 0)
		pr_err("message recv failed");

	if (cmd.magic != LOADTRACER_CMD_MAGIC)
		pr_err_ns("invalid message\n");

	switch (cmd.type) {
		case LIBLODAER_SET_ENV:
			recv_env_cmd(sock, cmd.len);
			break;
		case LIBLOADER_DL_OPEN:
			recv_dlopen_cmd(sock, cmd.len);
			break;
		case LIBLOADER_DL_CLOSE:
			recv_dlclose_cmd(sock, cmd.len);
			break;
		case LIBLOADER_START_TRACING:
			recv_start_tracing_cmd(sock, cmd.len);
			break;
		case LIBLOADER_STOP_TRACING:
			recv_stop_tracing_cmd(sock, cmd.len);
			break;
		default:
			break;
	}
}

static int listen_socket(const char *socket_path){
	struct sockaddr_un addr;
	int sock;
	if ( (sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket socket error");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
	unlink(socket_path);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
   		pr_err("socket bind error");
		return -1;
	}

	if (listen(sock, 1) == -1) {
    	pr_err("socket listen error");
		return -1;
	}

	return sock;
}

void *cmd_handler_thread(void *arg)
{
	char *libloader_sock_path;

	mkdir(LIBLOADER_SOCKET_DIR, 0755);
	xasprintf(&libloader_sock_path, "%s/%i", LIBLOADER_SOCKET_DIR, getpid());
	libloader_sock = listen_socket(libloader_sock_path);
	pr_dbg2("accepting socket : %s", libloader_sock_path);
	free(libloader_sock_path);

	libloader_efd = epoll_create1(EPOLL_CLOEXEC);
	if (libloader_efd < 0)
		pr_err("epoll error");

	epoll_add(libloader_efd, libloader_sock, EPOLLIN);	

	while (1) {
		struct epoll_event ev[10];
		int i, len;

		len = epoll_wait(libloader_efd, ev, 10, -1);
		if (len < 0)
			pr_err("epoll wait failed");

		for (i = 0; i < len; i++) {
			if (ev[i].data.fd == libloader_sock)
				handle_server_sock(&ev[i], libloader_efd);
			else
				handle_libloader_cmd(&ev[i], libloader_efd);
		}
	}

	close(libloader_efd);
	close(libloader_sock);

	return NULL;
}

static void libloader_startup(void)
{
	outfp = stdout;
	logfp = stderr;

	/* TODO parse arg for debug domains */
	dbg_domain[DBG_LIBLOADER] = DBG_LEVEL_3;
	debug = 1;

	pthread_t listener_thread;
	pthread_create(&listener_thread, NULL, cmd_handler_thread, NULL);
	pthread_detach(listener_thread);
}

static void libloader_cleanup(void)
{
	close(libloader_efd);
	close(libloader_sock);
}

static void __attribute__((constructor))
libloader_init(void)
{
	libloader_startup();
}

static void __attribute__((destructor))
libloader_fini(void)
{
	libloader_cleanup();
}