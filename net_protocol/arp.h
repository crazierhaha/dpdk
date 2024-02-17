#ifndef __ARP_H__
#define __ARP_H__

#include "common.h"
#include <rte_timer.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))

struct arp_entry {
	uint32_t ip;
	struct rte_ether_addr mac;
	uint8_t type;

	struct arp_entry *next;
};

struct arp_table {
	struct arp_entry *entries;
	uint32_t count;

	uint32_t localIp;
	struct rte_ether_addr localMac;
};

// 创建arp table实例
void arp_init(uint16_t port_id);

void arp_show(void);
void arp_add_entry(uint32_t ip, struct rte_ether_addr mac, uint8_t type);
struct arp_entry *arp_find(uint32_t);

struct rte_mbuf *arp_pkt_creator(struct rte_mempool *tx_mbuf_pool, uint16_t opcode,
									   const struct rte_ether_addr * const src_mac, const struct rte_ether_addr * const dst_mac,
									   uint32_t sip, uint32_t dip);

struct rte_ether_addr *arp_get_mac_with_ip(uint32_t dip, struct rte_mempool *tx_mbuf_pool);
struct rte_ether_addr *arp_get_local_mac(void);
uint32_t arp_get_local_ip(void);

// ARP request 定时器发包的回调函数
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg);

// ARP 包处理
void kr_arp_procedure(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool);

#endif // __ARP_H__ 

