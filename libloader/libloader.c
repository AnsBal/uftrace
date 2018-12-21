#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <dlfcn.h>

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
void* handle;

static void recv_dlclose_msg(int sock, int len)
{
	close(handle);
}
static void recv_dlopen_msg(int sock, int len)
{
	void *buffer;
	struct libloader_msg_dlopen msg_dlopen;
	unsigned int msg_env_len;
	char* exename;


	if (len < sizeof(msg_dlopen))
			pr_err_ns("invalid message length\n");

	if (read_all(sock, &msg_dlopen, sizeof(msg_dlopen)) < 0)
		pr_err("recv msg_env failed");

	exename = xmalloc(msg_dlopen.namelen + 1);
	if (read_all(sock, exename, msg_dlopen.namelen) < 0)
		pr_err("recv msg_env failed");
	exename[msg_dlopen.namelen] = '\0';

	handle = dlopen(exename, msg_dlopen.flags);
	if (!handle) {
		pr_err("dlopen request failed");
	}
	
	free(exename);
}

static void recv_env_msg(int sock, int len)
{
	void *buffer;
	struct libloader_msg_env msg_env;
	unsigned int msg_env_len;
	char* varname;
	char* value;

	if (len < sizeof(msg_env))
			pr_err_ns("invalid message length\n");

	if (read_all(sock, &msg_env, sizeof(msg_env)) < 0)
		pr_err("recv msg_env failed");

	varname = xmalloc(msg_env.len + 1);
	if (read_all(sock, varname, msg_env.len) < 0)
		pr_err("recv msg_env failed");
	varname[msg_env.len] = '\0';

	if (read_all(sock, &msg_env, sizeof(msg_env)) < 0)
		pr_err("recv msg_env failed");

	value = xmalloc(msg_env.len + 1);
	if (read_all(sock, value, msg_env.len) < 0)
		pr_err("recv msg_env failed");
	value[msg_env.len] = '\0';

	if(setenv(varname, value, 1) == -1)
		pr_err("setenv request failed");

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

static void handle_libloader_msg(struct epoll_event *ev, int efd)
{
	int sock = ev->data.fd;
	struct libloader_msg msg;

	if (ev->events & (EPOLLERR | EPOLLHUP)) {
		pr_dbg("client socket closed\n");
		
		if (epoll_ctl(efd, EPOLL_CTL_DEL, sock, NULL) < 0)
			pr_err("epoll del failed");

		close(sock);
		return;
	}

	if (read_all(sock, &msg, sizeof(msg)) < 0)
		pr_err("message recv failed");

	if (msg.magic != LOADTRACER_MSG_MAGIC)
		pr_err_ns("invalid message\n");

	switch (msg.type) {
	case LIBLODAER_SET_ENV:
		recv_env_msg(sock, msg.len);
		break;
	case LIBLOADER_DL_OPEN:
		recv_dlopen_msg(sock, msg.len);
		break;
	case LIBLOADER_DL_CLOSE:
		recv_dlclose_msg(sock, msg.len);
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

void *msg_handler_thread(void *arg)
{
	char *pathname = NULL;

	mkdir(SOCKET_DIR, 0755);
	//asprintf(&pathname, "%s/%i", SOCKET_DIR, getpigetpid());
	asprintf(&pathname, "%s/%s", SOCKET_DIR, "sock");
	libloader_sock = listen_socket(pathname);
	free(pathname);

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
				handle_libloader_msg(&ev[i], libloader_efd);
		}
	}

	close(libloader_efd);
	close(libloader_sock);

	return NULL;
}

static void libloader_startup(void)
{
	// Create thread
	pthread_t listener_thread;
	pthread_create(&listener_thread, NULL, msg_handler_thread, NULL);
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