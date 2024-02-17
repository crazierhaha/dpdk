#ifndef __SOCKET_COMMON_H__
#define __SOCKET_COMMON_H__

#include <stdint.h>
#include <pthread.h>

// 标识 tcp 流，或者 udp 连接，在 kr_tcp.c 或者 kr_udp.c 创建
struct kr_sock {
	int fd;

	// 五元组，唯一标识一个tcp流
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint8_t  protocol;

	struct kr_sock *prev;
	struct kr_sock *next;

	struct rte_ring *sndring;
	struct rte_ring *rcvring;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

	struct {
			uint32_t status;
			uint32_t seqnum;
			uint32_t acknum;
	} tcp;
	struct {} udp;
};

#endif
