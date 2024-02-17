#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <rte_ethdev.h>
#include <arpa/inet.h>

// 全局变量定义
extern volatile int g_exit_flag;

// 收发 mempool 中的 mbuf 数量
#define TXRX_MBUF_SIZE (4096-1)
#define TXRX_RING_SIZE	1024
#define SEND_RECV_RING_SIZE TXRX_RING_SIZE
#define TXRX_BURST_SIZE 512

// DEBUG
void print_mac(struct rte_ether_addr *mac);

// 简单做法，不考虑各线程的 socket，统一管理 ring。
struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};

// 单例模式 - 创建ring
struct inout_ring *ringInstance(void);

// DEBUG 相关
#define DEBUG 1
#ifdef DEBUG
#define debug_start() do { \
	printf("[%s]Start.\n", __func__); \
} while (0)

#define debug_end() do { \
	printf("[%s]End.\n", __func__); \
} while (0)

#define debug_step(num) do { \
	printf("[%s]%d.\n", __func__, num); \
} while (0)
#else
#define debug_start() (void;)
#define debug_end() (void;)
#define debug_step(num) (void;)
#endif



static inline void print_head(const char *func, struct rte_mbuf *mbuf) {
	struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	char macfmt[RTE_ETHER_ADDR_FMT_SIZE] = {0};
	rte_ether_format_addr(macfmt, RTE_ETHER_ADDR_FMT_SIZE, &ethhdr->s_addr);
	printf("[DEBUG][%s]pkt: src mac:%s  ", func, macfmt);

	rte_ether_format_addr(macfmt, RTE_ETHER_ADDR_FMT_SIZE, &ethhdr->d_addr);
	printf("dst mac:%s  ", macfmt);

	if (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) != ethhdr->ether_type) {
		printf("\n");
		return;
	}

	struct rte_ipv4_hdr *ipv4hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	// DEBUG
	if (1) {
		struct in_addr addr;
		addr.s_addr = ipv4hdr->src_addr;
		printf("(%s --> ", inet_ntoa(addr));
		addr.s_addr = ipv4hdr->dst_addr;
		printf("%s)\n", inet_ntoa(addr));
	}

}


#endif // __COMMON_H__
