#ifndef __ARP_H__
#define __ARP_H__

#include <rte_ether.h>
#include <rte_malloc.h>

struct arp_entry {
	uint32_t ip;
	struct rte_ether_addr mac;
	uint8_t type;

	struct arp_entry *next;
};

struct arp_table {
	struct arp_entry *entries;
	uint32_t count;
};

// 创建arptable实例
void arp_init(void);
void arp_show(void);
void arp_add_entry(uint32_t ip, struct rte_ether_addr mac, uint8_t type);
struct arp_entry *arp_find(uint32_t ip);

#endif // __ARP_H__
