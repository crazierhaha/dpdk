#include "kr_socket.h"

#include <stdio.h>
#include <stdint.h>

#include "kr_tcp.h"
#include "fd.h"


#define MAX_FILE_DESC_SIZE 1024

int kr_socket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}
	int fd = -1;
	if (type == SOCK_DGRAM) {

	} else if (type == SOCK_STREAM) { // tcp
		//≥ı ºªØ tcp
		kr_tcp_init();
		fd = kr_create_tcp_socket();

		if (fd <= 0) {
			return -1;
		}

	} else {
		printf("Error: kr_socket failed, for unvalid type.\n");
	}

	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}


	return fd;
}

int kr_bind(int sockfd, const struct sockaddr *addr, __attribute__((unused)) socklen_t addrlen) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}

	if (sockfd <= 2 || sockfd >= MAX_FILE_DESC_SIZE) {
		printf("[%s]Error: kr_bind failed for invalide sockfd[%d].\n", __func__, sockfd);
		return -1;
	}

	struct kr_sock *sock = get_tcp_entry_by_fd(sockfd);
	if (sock == NULL) {
		printf("[%s]Error: failed for not create socket identified by sockfd[%d].\n", __func__, sockfd);
		return -1;
	}

	const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;

	sock->sip = laddr->sin_addr.s_addr;
	sock->sport = laddr->sin_port;

	sock->tcp.status = KR_TCP_STATUS_CLOSED;
	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	return 0;
}

int kr_listen(int sockfd, __attribute__((unused)) int backlog) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}

	if (sockfd <= 2 || sockfd >= MAX_FILE_DESC_SIZE) {
		printf("[%s]Error: failed for invalide sockfd[%d].\n", __func__, sockfd);
		return -1;
	}

	struct kr_sock *sock = get_tcp_entry_by_fd(sockfd);
	if (sock == NULL) {
		printf("[%s]Error: failed for not create socket identified by sockfd[%d].\n", __func__, sockfd);
		return -1;
	}

	if (sock->protocol == IPPROTO_TCP) {
		sock->tcp.status = KR_TCP_STATUS_LISTEN;
	}
	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	return 0;
}


int kr_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}

	int connfd = -1;
	connfd = kr_accept_tcp_socket(sockfd);
	if (connfd < 0) {
		printf("[%s]kr_accept_tcp_socket[%d] failed.\n", __func__, sockfd);
		return -1;
	}

	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	return connfd;
}

ssize_t kr_read(int fd, void *buf, size_t count) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}
	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	return 0;


}
ssize_t kr_write(int fd, const void *buf, size_t nbytes) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}
	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	return 0;

}

int kr_close(int fd) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}
	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	return 0;

}






