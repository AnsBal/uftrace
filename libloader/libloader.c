#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>

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
		pr_red("epoll add failed");
}

static void send_reply(int sock, unsigned short type)
{
	struct libloader_reply reply = {
		.magic = LOADTRACER_REPLY_MAGIC,
		.type = type,
	};
	struct iovec iov[1] = {
		{ .iov_base = &reply, .iov_len = sizeof(reply), },
	};
	int len = sizeof(reply);

	if (sock < 0)
		return;

	if (writev(sock, iov, 1) != len) {
		/* TODO normal stop */
		/*if (!mcount_should_stop())
			pr_red("write tid info failed");*/
		printf("send_reply couldnt write all bytes\n");
	}
}

/* TODO use a more generic function instead (recv_exec_func) */
static void recv_start_tracing_request(int sock, int len)
{
	struct libloader_request_start_tracing request_start_tracing;
	char* libname;
	unsigned short reply_type = LIBLODAER_SUCESS;

	if (len < sizeof(request_start_tracing)){
		pr_red("invalid message length\n");
		reply_type = LIBLOADER_FAILURE;
	}

	if (read_all(sock, &request_start_tracing, sizeof(request_start_tracing)) < 0) {
		pr_red("recv request_start_tracing failed");
		reply_type = LIBLOADER_FAILURE;
	}

	libname = xmalloc(request_start_tracing.namelen + 1);
	if (read_all(sock, libname, request_start_tracing.namelen) < 0) {
		pr_red("recv request_start_tracing failed");
		reply_type = LIBLOADER_FAILURE;
	}
	libname[request_start_tracing.namelen] = '\0';
	
	void* handle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
	if (!handle) {
		pr_red("start tracing failed");
		reply_type = LIBLOADER_FAILURE;
	}
	
	void (*start_tracing)(void);
	start_tracing = dlsym(handle, "start_tracing");
	if (!start_tracing) {
		pr_red("start tracing request failed");		
		reply_type = LIBLOADER_FAILURE;
	}

	pr_dbg2("request TRACEON: %s\n", libname);
	start_tracing();	
	send_reply(sock, reply_type);
	free(libname);
}

static void recv_stop_tracing_request(int sock, int len)
{
	struct libloader_request_stop_tracing request_stop_tracing;
	char* libname;
	unsigned short reply_type = LIBLODAER_SUCESS;

	if (len < sizeof(request_stop_tracing)){
		pr_red("invalid message length\n");
		reply_type = LIBLOADER_FAILURE;
	}

	if (read_all(sock, &request_stop_tracing, sizeof(request_stop_tracing)) < 0) {
		pr_red("recv request_stop_tracing failed");
		reply_type = LIBLOADER_FAILURE;
	}

	libname = xmalloc(request_stop_tracing.namelen + 1);
	if (read_all(sock, libname, request_stop_tracing.namelen) < 0) {
		pr_red("recv request_stop_tracing failed");
		reply_type = LIBLOADER_FAILURE;
	}
	libname[request_stop_tracing.namelen] = '\0';
	
	void* handle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
	if (!handle) {
		pr_red("stop tracing failed");
		reply_type = LIBLOADER_FAILURE;
	}
	
	void (*stop_tracing)(void);
	stop_tracing = dlsym(handle, "stop_tracing");
	if (!stop_tracing) {
		pr_red("stop tracing request failed");		
		reply_type = LIBLOADER_FAILURE;
	}

	pr_dbg2("request TRACEOFF: %s\n", libname);
	stop_tracing();
	send_reply(sock, reply_type);
	free(libname);
}

static void recv_dlclose_request(int sock, int len)
{
	/* TODO clean multiple dlclose */
	struct libloader_request_dlclose request_dlclose;
	char* libname;
	unsigned short reply_type = LIBLODAER_SUCESS;

	if (len < sizeof(request_dlclose)) {
		pr_red("invalid message length\n");
		reply_type = LIBLOADER_FAILURE;
	}

	if (read_all(sock, &request_dlclose, sizeof(request_dlclose)) < 0){
		pr_red("recv request_dlclose failed");
		reply_type = LIBLOADER_FAILURE;
	}

	libname = xmalloc(request_dlclose.namelen + 1);
	if (read_all(sock, libname, request_dlclose.namelen) < 0) {
		pr_red("recv request_dlclose failed");
		reply_type = LIBLOADER_FAILURE;
	}
	libname[request_dlclose.namelen] = '\0';
	
	void* handle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
	if (!handle) {
		pr_red("dlclose request failed");
		reply_type = LIBLOADER_FAILURE;
	}

	if (dlclose(handle)) {
		pr_red("dlclose request failed");
		reply_type = LIBLOADER_FAILURE;
	} 
	if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}
	if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}
	if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}
		if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}		if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}		if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}		if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}		if (dlclose(handle)) {
		pr_red("dlclose request failed");
	}
	
	pr_dbg2("request DLCLOSE: %s: %p\n", libname, handle);
	send_reply(sock, reply_type);
	free(libname);
}

static void recv_dlopen_request(int sock, int len)
{
	struct libloader_request_dlopen request_dlopen;
	char* libname;
	unsigned short reply_type = LIBLODAER_SUCESS;

	if (len < sizeof(request_dlopen)) {
		pr_red("invalid message length\n");
		reply_type = LIBLOADER_FAILURE;
	}

	if (read_all(sock, &request_dlopen, sizeof(request_dlopen)) < 0) {
		pr_red("recv request_env failed");
		reply_type = LIBLOADER_FAILURE;
	}

	libname = xmalloc(request_dlopen.namelen + 1);
	if (read_all(sock, libname, request_dlopen.namelen) < 0){
		pr_red("recv request_env failed");
		reply_type = LIBLOADER_FAILURE;
	}
	libname[request_dlopen.namelen] = '\0';

	void* handle = dlopen(libname, request_dlopen.flags);
	if (!handle) {
		pr_red("dlopen request failed");
		reply_type = LIBLOADER_FAILURE;
	}
	
	pr_dbg2("request DLOPEN: %s\n", libname);
	send_reply(sock, reply_type);
	free(libname);
}

static void recv_env_request(int sock, int len)
{
	struct libloader_request_env request_env;
	char *varname;
	char *value;
	unsigned short reply_type = LIBLODAER_SUCESS;

	if (len < sizeof(request_env)){
		pr_red("invalid message length\n");
		reply_type = LIBLOADER_FAILURE;
	}

	if (read_all(sock, &request_env, sizeof(request_env)) < 0){
		pr_red("recv request_env failed");
		reply_type = LIBLOADER_FAILURE;
	}

	varname = xmalloc(request_env.len + 1);
	if (read_all(sock, varname, request_env.len) < 0){
		pr_red("recv request_env failed");
		reply_type = LIBLOADER_FAILURE;
	}
	varname[request_env.len] = '\0';

	if (read_all(sock, &request_env, sizeof(request_env)) < 0){
		pr_red("recv request_env failed");
		reply_type = LIBLOADER_FAILURE;
	}

	value = xmalloc(request_env.len + 1);
	if (read_all(sock, value, request_env.len) < 0){
		pr_red("recv request_env failed");
		reply_type = LIBLOADER_FAILURE;
	}
	value[request_env.len] = '\0';

	if(setenv(varname, value, 1) == -1) {
		pr_red("setenv request failed");
		reply_type = LIBLOADER_FAILURE;
	}

	pr_dbg3("request SETENV: %s: %s \n", varname, value);
	send_reply(sock, reply_type);
	free(varname);
	free(value);
}

static void handle_server_sock(struct epoll_event *ev, int efd)
{
	int client;
	int sock = ev->data.fd;

	client = accept(sock, NULL, NULL);
	if (client < 0)
		pr_red("socket accept failed");

	epoll_add(efd, client, EPOLLIN);
}

static void handle_libloader_request(struct epoll_event *ev, int efd)
{
	int sock = ev->data.fd;
	struct libloader_request request;

	if (ev->events & (EPOLLERR | EPOLLHUP)) {
		pr_dbg("client socket closed\n");
		
		if (epoll_ctl(efd, EPOLL_CTL_DEL, sock, NULL) < 0)
			pr_red("epoll del failed");

		close(sock);
		return;
	}

	if (read_all(sock, &request, sizeof(request)) < 0)
		pr_red("message recv failed");

	if (request.magic != LOADTRACER_REQUEST_MAGIC)
		pr_red("invalid message\n");

	switch (request.type) {
		case LIBLODAER_SET_ENV:
			recv_env_request(sock, request.len);
			break;
		case LIBLOADER_DL_OPEN:
			recv_dlopen_request(sock, request.len);
			break;
		case LIBLOADER_DL_CLOSE:
			recv_dlclose_request(sock, request.len);
			break;
		case LIBLOADER_START_TRACING:
			recv_start_tracing_request(sock, request.len);
			break;
		case LIBLOADER_STOP_TRACING:
			recv_stop_tracing_request(sock, request.len);
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
   		pr_red("socket bind error");
		return -1;
	}

	if (listen(sock, 1) == -1) {
    	pr_red("socket listen error");
		return -1;
	}

	return sock;
}

void *request_handler_thread(void *arg)
{
	char *libloader_sock_path;

	mkdir(LIBLOADER_SOCKET_DIR, 0755);
	xasprintf(&libloader_sock_path, "%s/%i", LIBLOADER_SOCKET_DIR, getpid());
	libloader_sock = listen_socket(libloader_sock_path);
	pr_dbg2("accepting socket : %s", libloader_sock_path);

	libloader_efd = epoll_create1(EPOLL_CLOEXEC);
	if (libloader_efd < 0)
		pr_red("epoll error");

	epoll_add(libloader_efd, libloader_sock, EPOLLIN);	

	while (1) {
		struct epoll_event ev[10];
		int i, len;

	retry:
		len = epoll_wait(libloader_efd, ev, 10, -1);
		if (len < 0) {
			if (errno == EINTR)
				goto retry;
		}

		for (i = 0; i < len; i++) {
			if (ev[i].data.fd == libloader_sock)
				handle_server_sock(&ev[i], libloader_efd);
			else
				handle_libloader_request(&ev[i], libloader_efd);
		}
	}

	close(libloader_efd);
	close(libloader_sock);
	unlink(libloader_sock_path);
	free(libloader_sock_path);

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
	pthread_create(&listener_thread, NULL, request_handler_thread, NULL);
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