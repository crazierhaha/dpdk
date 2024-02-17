#ifndef __TCP_H__
#define __TCP_H__

#include <stdint.h>
#include <rte_mbuf.h>

#include "socket_common.h"
#include "list.h"

extern struct kr_tcp_table *g_tcp_table;

// 定义 tcp status
enum KR_TCP_STATUS {
	KR_TCP_STATUS_CLOSED = 0,	// server, client
	KR_TCP_STATUS_LISTEN,		// server
	KR_TCP_STATUS_SYN_RCVD,		// server
	KR_TCP_STATUS_SYN_SENT,		// client
	KR_TCP_STATUS_ESTABLISHED,	// server/client

	// 断开 tcp 连接
	KR_TCP_STATUS_FIN_WAIT_1,	// client
	KR_TCP_STATUS_FIN_WAIT_2,	// client
	KR_TCP_STATUS_CLOSING,		// server/client
	KR_TCP_STATUS_TIME_WAIT,	// server

	KR_TCP_STATUS_CLOSE_WAIT,	// client
	KR_TCP_STATUS_LAST_ACK		// server
};

struct kr_tcp_table;
struct kr_tcp_entry {
	struct kr_sock tcp_stream;

	struct kr_tcp_table *syn_table;
	struct kr_tcp_table *accept_table;

	struct kr_tcp_entry *prev;
	struct kr_tcp_entry *next;
};

struct kr_tcp_table {
	struct kr_tcp_entry *entries;
	int count;
};

struct kr_tcp_header {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint32_t seqnum;
	uint32_t acknum;
	uint8_t hlen;
	uint8_t flags;
	uint16_t windows;
	uint16_t cksum;
	uint16_t ptr;

	uint32_t optlen;
	uint32_t option[10]; // tcp 选项最长40字节
	uint8_t *data;
	uint32_t dlen;

};

void kr_tcp_init(void);
int kr_create_tcp_socket(void);
int kr_accept_tcp_socket(int fd);

struct kr_tcp_table *get_tcp_table(void);
struct kr_tcp_entry *get_tcp_entry_by_fd(int fd);

int kr_tcp_procedure(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool);


#endif
