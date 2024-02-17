#include "kr_tcp.h"

#include <pthread.h>
#include <rte_malloc.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "common.h"
#include "list.h"
#include "fd.h"

#define MAX_TCP_SEQ_NUM  4294967295
#define TCP_DEFAULT_WINDOW  14600


// g_tcp_table 表示已经建立连接（或由 socket 接口创建）的 tcp 数据结构的链表
struct kr_tcp_table *g_tcp_table = NULL;
static pthread_cond_t g_table_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_table_mutex = PTHREAD_MUTEX_INITIALIZER;


// ?
void kr_tcp_init(void) {
	debug_start();
	(void)g_table_cond;
	(void)g_table_mutex;
	if (g_tcp_table == NULL) {
		pthread_mutex_lock(&g_table_mutex);
		if (g_tcp_table == NULL) {
			printf("[%s]init: create tcp table.\n", __func__);
			g_tcp_table = rte_malloc("TCP Table", sizeof(struct kr_tcp_table), 0);
			if (g_tcp_table == NULL) {
				pthread_mutex_unlock(&g_table_mutex);
				rte_exit(EXIT_FAILURE, "Error: create tcp table failed.\n");
			}
			memset(g_tcp_table, 0, sizeof(struct kr_tcp_table));
		}
		pthread_mutex_unlock(&g_table_mutex);
	}

	debug_end();
}

struct kr_tcp_table *get_tcp_table(void) {
	if (g_tcp_table == NULL) {
		kr_tcp_init();
	}

	return g_tcp_table;
}

struct kr_tcp_entry *get_tcp_entry_by_fd(int fd) {
debug_start();
	struct kr_tcp_entry *iter = get_tcp_table()->entries;
	while (iter != NULL) {
		if (iter->tcp_stream.fd == fd) {
			debug_end();
			return iter;
		}
		iter = iter->next;
	}

	return NULL;
}

// ???�连?�队??
static struct kr_tcp_entry *get_tcp_syn_entry(struct kr_tcp_entry *tbl, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
	debug_start();

	if (tbl == NULL || tbl->syn_table == NULL) {
		debug_end();
		return NULL;
	}

	struct kr_tcp_entry *iter = tbl->syn_table->entries;
	while (iter != NULL) {
		if (iter->tcp_stream.sip == dip && iter->tcp_stream.dip == sip && iter->tcp_stream.sport == dport && iter->tcp_stream.dport == sport) {
			debug_end();
			printf("[%s]%p\n", __func__, iter);
			return iter;
		}
		iter = iter->next;
	}

	debug_end();
	return NULL;
}

// ???��??�队??
static struct kr_tcp_entry *get_tcp_accept_entry(struct kr_tcp_entry *tbl, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
	debug_start();

	if (tbl == NULL || tbl->accept_table == NULL) {
		debug_end();
		return NULL;
	}

	struct kr_tcp_entry *iter = tbl->accept_table->entries;
	while (iter != NULL) {
		if (iter->tcp_stream.sip == dip && iter->tcp_stream.dip == sip && iter->tcp_stream.sport == dport && iter->tcp_stream.dport == sport) {
			debug_end();
			return iter;
		}
		iter = iter->next;
	}

	debug_end();
	return NULL;
}

static struct kr_tcp_entry *get_tcp_entry(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
	debug_start();
	printf("%d %d\n", ntohs(sport), ntohs(dport));
	struct kr_tcp_entry *iter = get_tcp_table()->entries;
	struct kr_tcp_entry *ret = NULL;
	while (iter != NULL) {
		if (iter->tcp_stream.sip == dip && iter->tcp_stream.dip == sip && iter->tcp_stream.sport == dport && iter->tcp_stream.dport == sport) {
			printf("[%s]%p\n", __func__, iter);
			debug_end();
			return iter;
		}
		if ((ret = get_tcp_syn_entry(iter, sip, dip, sport, dport)) != NULL) {
			debug_end();
			return ret;
		}
		if ((ret = get_tcp_accept_entry(iter, sip, dip, sport, dport)) != NULL) {
			debug_end();
			return ret;
		}
		iter = iter->next;
	}

	// 查找由 socket api 创建的 tcp 连接 - listen
	iter = get_tcp_table()->entries;
	while (iter != NULL) {
		if (iter->tcp_stream.dip == 0 && iter->tcp_stream.dport == 0 && iter->tcp_stream.sport == dport) {
			debug_end();
			printf("[%s]%p\n", __func__, iter);
			return iter;
		}
		iter = iter->next;
	}

	debug_end();

	return NULL; // 表示 tcp 的 已连接（或 socket 创建的）、全连接和半连接表中未找到该 tcp 数据结构
}

// 创建表示 tcp 连接的数据结构
static struct kr_tcp_entry *create_tcp_entry(void) {
	debug_start();

	struct kr_tcp_entry *tcp_entry = rte_malloc("TCP Entry", sizeof(struct kr_tcp_entry), 0);
	if (tcp_entry == NULL) {
		printf("Error: kr_create_tcp_socket malloc failed.\n");
		return NULL;
	}
	memset(tcp_entry, 0, sizeof(*tcp_entry));
	pthread_cond_init(&tcp_entry->tcp_stream.cond, NULL);
	pthread_mutex_init(&tcp_entry->tcp_stream.mutex, NULL);

	uint32_t next_seed = time(NULL);
	tcp_entry->tcp_stream.tcp.seqnum = rand_r(&next_seed) % MAX_TCP_SEQ_NUM;

	debug_end();
	return tcp_entry;
}

// 创建 socket
extern int kr_create_tcp_socket(void) {
	debug_start();

	struct kr_tcp_entry *tcp_entry = create_tcp_entry();

	// 获取 fd
	tcp_entry->tcp_stream.fd = get_fd();
	tcp_entry->tcp_stream.protocol = IPPROTO_TCP;

	//创建 socket 的 ringBuffer
	tcp_entry->tcp_stream.sndring = rte_ring_create("TCP send ring", SEND_RECV_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (tcp_entry->tcp_stream.sndring == NULL) {
		printf("[%s]Error: kr_create_tcp_socket create ring failed.\n", __func__);
		return -1;
	}
	tcp_entry->tcp_stream.rcvring = rte_ring_create("TCP recv ring", SEND_RECV_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (tcp_entry->tcp_stream.rcvring == NULL) {
		printf("[%s]Error: kr_create_tcp_socket create ring failed.\n", __func__);
		rte_ring_free(tcp_entry->tcp_stream.sndring);
		return -1;
	}

	// 创建 syn table 和 accept table
	tcp_entry->syn_table = rte_malloc("TCP SYN TABLE", sizeof(struct kr_tcp_table), 0);
	if (tcp_entry->syn_table == NULL) {
		rte_ring_free(tcp_entry->tcp_stream.sndring);
		rte_ring_free(tcp_entry->tcp_stream.rcvring);
		printf("[%s]rte_malloc syn table failed.\n", __func__);
		return -1;
	}
	memset(tcp_entry->syn_table, 0, sizeof(struct kr_tcp_table));

	tcp_entry->accept_table = rte_malloc("TCP ACCEPT TABLE", sizeof(struct kr_tcp_table), 0);
	if (tcp_entry->accept_table == NULL) {
		rte_ring_free(tcp_entry->tcp_stream.sndring);
		rte_ring_free(tcp_entry->tcp_stream.rcvring);
		rte_free(tcp_entry->syn_table);
		printf("[%s]rte_malloc accept table failed.\n", __func__);
		return -1;
	}
	memset(tcp_entry->syn_table, 0, sizeof(struct kr_tcp_table));

	pthread_mutex_lock(&g_table_mutex);
	LIST_ADD(get_tcp_table(), tcp_entry);
	pthread_mutex_unlock(&g_table_mutex);

	debug_end();

	return tcp_entry->tcp_stream.fd;
}

// 从 fd 表示的 tcp_entry 的 accept table 中取出第一个 tcp_entry，返回其 fd
int kr_accept_tcp_socket(int fd) {
debug_start();

	struct kr_tcp_entry *tcp_socket_entry = get_tcp_entry_by_fd(fd);
	if (tcp_socket_entry == NULL) {
		printf("[%s]get socket[%d] tcp entry failed.\n", __func__, fd);
	}

	// 从 tcp_entry 的 accept table 中取一个数据
	struct kr_tcp_entry *tcp_entry = NULL;
	do { // 没有连接就阻塞在这里
		tcp_entry = tcp_socket_entry->accept_table->entries;
		sleep(3);
		printf("[%s] while.\n", __func__);
	} while (tcp_entry == NULL);

	printf("%p\n", tcp_entry);

	debug_step(1);
 	LIST_DEL(tcp_socket_entry->accept_table, tcp_entry);

	// 给 tcp_entry 赋值一个 fd
	debug_step(3);
	tcp_entry->tcp_stream.fd = get_fd();
	char ring_name[256] = {0};
	// 给 tcp_entry 创建自己的 sndring/rcvring
	snprintf(ring_name, 256, "TCP send ring%d", fd);
	tcp_entry->tcp_stream.sndring = rte_ring_create(ring_name, SEND_RECV_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (tcp_entry->tcp_stream.sndring == NULL) {
		printf("[%s]Error: kr_create_tcp_socket create ring failed.\n", __func__);
		return -1;
	}
	snprintf(ring_name, 256, "TCP recv ring%d", fd);
	tcp_entry->tcp_stream.rcvring = rte_ring_create("TCP recv ring1", SEND_RECV_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (tcp_entry->tcp_stream.rcvring == NULL) {
		printf("[%s]Error: kr_create_tcp_socket create ring failed.\n", __func__);
		rte_ring_free(tcp_entry->tcp_stream.sndring);
		return -1;
	}

	// 将 tcp_entry 加到 tcp 的已连接队列中
	debug_step(2);
	LIST_ADD(get_tcp_table(), tcp_entry);

debug_end();

	return tcp_entry->tcp_stream.fd;
}

static struct rte_mbuf *kr_tcp_encode(const struct kr_tcp_header *tcp_header, struct rte_mempool *tx_mbuf_pool) {
	debug_start();

	struct rte_mbuf *tx_mbuf = rte_pktmbuf_alloc(tx_mbuf_pool);
	if (tx_mbuf == NULL) {
		printf("[%s]Error: create mbuf failed.\n", __func__);
		return NULL;
	}

	const uint32_t total_len =
		tcp_header->dlen + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + tcp_header->optlen * sizeof(uint32_t);

	// �
	struct rte_ipv4_hdr *ipv4hdr = rte_pktmbuf_mtod_offset(tx_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(ipv4hdr + 1);

	// 1. ip
	ipv4hdr->src_addr = tcp_header->sip;
	ipv4hdr->dst_addr = tcp_header->dip;
	ipv4hdr->version_ihl = 0x45;
	ipv4hdr->type_of_service = 0;
	ipv4hdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ipv4hdr->packet_id = 0;
	ipv4hdr->fragment_offset = 0;
	ipv4hdr->time_to_live = 64;
	ipv4hdr->next_proto_id = IPPROTO_TCP;
	ipv4hdr->hdr_checksum = 0;
	ipv4hdr->hdr_checksum = rte_ipv4_cksum(ipv4hdr);

	// 2. tcp
	tcphdr->src_port = tcp_header->sport;
	tcphdr->dst_port = tcp_header->dport;
	tcphdr->sent_seq = htonl(tcp_header->seqnum);
	tcphdr->recv_ack = htonl(tcp_header->acknum);

	tcphdr->data_off = tcp_header->hlen;
	tcphdr->rx_win = tcp_header->windows;
	tcphdr->tcp_urp = tcp_header->ptr;
	tcphdr->tcp_flags = tcp_header->flags;

	// 处理 tcp 的payload
	if (tcp_header->data != NULL) {
		uint8_t *payload = (uint8_t *)(tcphdr + 1) + tcp_header->optlen * sizeof(uint32_t);
		rte_memcpy(payload, tcp_header->data, tcp_header->dlen);
	}

	tcphdr->cksum = 0;
	tcphdr->cksum = rte_ipv4_udptcp_cksum(ipv4hdr, tcphdr);
	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	tx_mbuf->pkt_len = total_len;
	tx_mbuf->data_len = total_len;

	return tx_mbuf;
}

static int kr_tcp_listen_pkt(struct kr_tcp_entry *tcp_entry, struct rte_ipv4_hdr *ipv4hdr, struct rte_tcp_hdr *tcphdr, struct rte_mempool *tx_mbuf_pool) {
	debug_start();
	if (tcp_entry->tcp_stream.tcp.status != KR_TCP_STATUS_LISTEN) {
		printf("[%s]tcp entry status is not listen status.\n", __func__);
		return -1;
	}

	// syn
	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		// 创建 tcp 连接
		struct kr_tcp_entry *new_tcp_entry = create_tcp_entry();
		if (new_tcp_entry == NULL) {
			printf("[%s]create tcp entry failed.\n", __func__);
			return -1;
		}

		new_tcp_entry->tcp_stream.sip = ipv4hdr->dst_addr; // ipv4_worker 中已经保证ipv4包中的 dst ip 等于 localIp
		new_tcp_entry->tcp_stream.dip = ipv4hdr->src_addr;
		new_tcp_entry->tcp_stream.sport = tcphdr->dst_port;
		new_tcp_entry->tcp_stream.dport = tcphdr->src_port;
		new_tcp_entry->tcp_stream.protocol = IPPROTO_TCP;

		new_tcp_entry->tcp_stream.tcp.acknum = ntohl(tcphdr->sent_seq) + 1;
		new_tcp_entry->tcp_stream.tcp.status = KR_TCP_STATUS_SYN_RCVD;

		LIST_ADD(tcp_entry->syn_table, new_tcp_entry);

		// 构造 syn + ack 包
		struct kr_tcp_header tcp_header;
		memset(&tcp_header, 0, sizeof(tcp_header));

		tcp_header.sip = new_tcp_entry->tcp_stream.sip;
		tcp_header.dip = new_tcp_entry->tcp_stream.dip;
		tcp_header.sport = new_tcp_entry->tcp_stream.sport;
		tcp_header.dport = new_tcp_entry->tcp_stream.dport;
		tcp_header.seqnum = new_tcp_entry->tcp_stream.tcp.seqnum;
		tcp_header.acknum = new_tcp_entry->tcp_stream.tcp.acknum;
		tcp_header.hlen = 0x50;

		tcp_header.flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;

		tcp_header.windows = TCP_DEFAULT_WINDOW;

		tcp_header.optlen = 0;

		struct rte_mbuf *tx_syn_ack = kr_tcp_encode(&tcp_header, tx_mbuf_pool);
		if (tx_syn_ack == NULL) {
			return -1;
		}

		rte_ring_mp_enqueue(tcp_entry->tcp_stream.sndring, (void *)tx_syn_ack);

	}


	debug_end();

	return 0;
}

static int kr_tcp_syn_rcvd_pkt(struct kr_tcp_entry *tcp_entry, __attribute__((unused)) struct rte_ipv4_hdr *ipv4hdr, struct rte_tcp_hdr *tcphdr, __attribute__((unused)) struct rte_mempool *tx_mbuf_pool) {
	debug_start();
	if (tcp_entry->tcp_stream.tcp.status != KR_TCP_STATUS_SYN_RCVD) {
		printf("[%s]tcp entry status is not syn recvd.\n", __func__);
		return -1;
	}
	// SYN_RCVD 状态只处理三次握手的 ack 包
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		// 判断 ACK 包的 seq 是否合法
		if (ntohl(tcphdr->sent_seq) != tcp_entry->tcp_stream.tcp.acknum) {
			printf("[%s]pkt seq[%d], tcp entry acknum[%d]\n", __func__, ntohl(tcphdr->sent_seq), tcp_entry->tcp_stream.tcp.acknum);
			return -1;
		}

		// 首先，获取该 tcp 请求对应的 socket 创建的 tcp 连接数据结构
		struct kr_tcp_entry *sock_tcp = get_tcp_entry(0, 0, 0, tcphdr->dst_port);
		if (sock_tcp == NULL) {
			printf("[%s]get socket tcp failed, dst_port[%d].\n", __func__, tcphdr->dst_port);
			return -1;
		}
		// 将对应的 tcp_entry 从 syn table 移到 accept table
		LIST_DEL(sock_tcp->syn_table, tcp_entry);
		LIST_ADD(sock_tcp->accept_table, tcp_entry);

		tcp_entry->tcp_stream.tcp.status = KR_TCP_STATUS_ESTABLISHED;
	}
	debug_end();

	return 0;
}

static int kr_tcp_send_ack(struct kr_tcp_entry *tcp_entry, __attribute__((unused)) struct rte_tcp_hdr *tcphdr, struct rte_mempool *tx_mbuf_pool) {
	debug_start();

	// 构造 ack 包
	struct kr_tcp_header tcp_header;
	memset(&tcp_header, 0, sizeof(tcp_header));

	tcp_header.sip = tcp_entry->tcp_stream.sip;
	tcp_header.dip = tcp_entry->tcp_stream.dip;
	tcp_header.sport = tcp_entry->tcp_stream.sport;
	tcp_header.dport = tcp_entry->tcp_stream.dport;
	tcp_header.seqnum = tcp_entry->tcp_stream.tcp.seqnum;
	tcp_header.acknum = tcp_entry->tcp_stream.tcp.acknum;
	tcp_header.hlen = 0x50;

	tcp_header.flags = RTE_TCP_ACK_FLAG;

	tcp_header.windows = TCP_DEFAULT_WINDOW;

	tcp_header.optlen = 0;

	struct rte_mbuf *tx_syn_ack = kr_tcp_encode(&tcp_header, tx_mbuf_pool);
	if (tx_syn_ack == NULL) {
		return -1;
	}

	rte_ring_mp_enqueue(tcp_entry->tcp_stream.sndring, (void *)tx_syn_ack);

	return 0;
	debug_end();
}

static int kr_tcp_established_pkt(struct kr_tcp_entry *tcp_entry, struct rte_ipv4_hdr *ipv4hdr, struct rte_tcp_hdr *tcphdr, struct rte_mempool *tx_mbuf_pool) {
	debug_start();
	if (tcp_entry->tcp_stream.tcp.status != KR_TCP_STATUS_ESTABLISHED) {
		printf("[%s]tcp entry status is not established.\n", __func__);
		return -1;
	}

	// 先判断 seq 是否正确
	if (htonl(tcphdr->sent_seq) != tcp_entry->tcp_stream.tcp.acknum) {
		printf("[%s]pkt seq[%d], tcp entry acknum[%d]\n", __func__, ntohl(tcphdr->sent_seq), tcp_entry->tcp_stream.tcp.acknum);
		return -1;
	}
	// SYN
	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {

	}

	// ACK
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}

	// PSH
	if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
		// 计算 tcp 包总长度
		uint32_t tcplen = 0;
		tcplen = ntohs(ipv4hdr->total_length) - sizeof(struct rte_ipv4_hdr);

		// 计算 tcp 头部长度
		uint8_t tcp_hdrlen;
		tcp_hdrlen = tcphdr->data_off >> 4;

		// 计算 payload 长度
		uint32_t payload_len;
		payload_len = tcplen - tcp_hdrlen * 4;

		//更新 tcp_entry 中的 seqnum 和 acknum
		printf("[%s]%d %d\n", __func__, tcp_entry->tcp_stream.tcp.seqnum, tcp_entry->tcp_stream.tcp.acknum);
		printf("[%s]payload length = %d\n", __func__, payload_len);
		tcp_entry->tcp_stream.tcp.acknum += payload_len;
		tcp_entry->tcp_stream.tcp.seqnum = ntohl(tcphdr->recv_ack);
		printf("[%s]%d %d\n", __func__, tcp_entry->tcp_stream.tcp.seqnum, tcp_entry->tcp_stream.tcp.acknum);

		// 回 ack 包
		kr_tcp_send_ack(tcp_entry, tcphdr, tx_mbuf_pool);

	}

	// FIN
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

	}

	debug_end();
	return 0;
}


//TCP 报文处理入口
int kr_tcp_procedure(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool) {
	debug_start();

	// 检查 tcp 的 checksum
	struct rte_ipv4_hdr *ipv4hdr = rte_pktmbuf_mtod_offset(in_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(ipv4hdr + 1);

	uint16_t cksum, tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;

	cksum = rte_ipv4_udptcp_cksum(ipv4hdr, tcphdr);

	if (tcpcksum != cksum) {
		printf("[%s]Warning: tcp checksum is invalid.\n", __func__);
		return -1;
	}

	// 查找 tcp 连接
	struct kr_tcp_entry *tcp_entry = get_tcp_entry(ipv4hdr->src_addr, ipv4hdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
	// 未找到 tcp 连接
	if (tcp_entry == NULL) {
		// DEBUG
		{
			printf("[%s]There is no tcp socket for this package.\n", __func__);
		}

		return -1;
	}
	printf("[%s]tcp_entry: %p\n", __func__, tcp_entry);
	// TCP 状态机
	switch (tcp_entry->tcp_stream.tcp.status) {
		case KR_TCP_STATUS_CLOSED:
			break;
		case KR_TCP_STATUS_LISTEN:
			kr_tcp_listen_pkt(tcp_entry, ipv4hdr, tcphdr, tx_mbuf_pool);
			break;
		case KR_TCP_STATUS_SYN_RCVD:
			kr_tcp_syn_rcvd_pkt(tcp_entry, ipv4hdr, tcphdr, tx_mbuf_pool);
			break;
		case KR_TCP_STATUS_SYN_SENT:
			break;
		case KR_TCP_STATUS_ESTABLISHED:
			kr_tcp_established_pkt(tcp_entry, ipv4hdr, tcphdr, tx_mbuf_pool);
			break;
		// tcp 断开相关状态
		case KR_TCP_STATUS_FIN_WAIT_1:
		case KR_TCP_STATUS_FIN_WAIT_2:
		case KR_TCP_STATUS_CLOSING:
		case KR_TCP_STATUS_TIME_WAIT:

		case KR_TCP_STATUS_CLOSE_WAIT:
		case KR_TCP_STATUS_LAST_ACK:
			break;
	}

	debug_end();
	return 0;
}

