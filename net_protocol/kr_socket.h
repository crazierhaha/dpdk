#ifndef __KR_SOCKET_H__
#define __KR_SOCKET_H__
#include <unistd.h>
#include <arpa/inet.h>

#include "socket_common.h"

extern int kr_socket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol);

int kr_bind(int sockfd, const struct sockaddr *addr, __attribute__((unused)) socklen_t addrlen);

int kr_listen(int sockfd, __attribute__((unused)) int backlog);

ssize_t kr_read(int fd, void *buf, size_t count);
ssize_t kr_write(int fd, const void *buf, size_t nbytes);
int kr_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int kr_close(int fd);

#endif
