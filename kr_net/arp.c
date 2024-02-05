#include <arpa/inet.h>

#include "arp.h"

static struct arp_table *g_arp_table = NULL;

const char *arp_type[2] = {"Static", "Dynamic"};

void arp_init(void) {
	printf("[arp]init: create arp table.\n");
	g_arp_table = rte_malloc("ARP table", sizeof(struct arp_table), 0);
	if (!g_arp_table) {
		rte_exit(EXIT_FAILURE, "Error: rte_malloc arp table failed.\n");
	}
	g_arp_table->entries = NULL;
	g_arp_table->count = 0;
}

struct arp_table *get_arp_table(void) {
	return g_arp_table;
}

// 查找
struct arp_entry *arp_find(uint32_t ip) {
	struct arp_entry *iterator = get_arp_table()->entries;

	while (iterator) {
		if (iterator->ip == ip) {
			return iterator;
		}

		iterator = iterator->next;
	}

	return NULL;
}

void arp_add_entry(uint32_t ip, struct rte_ether_addr mac, uint8_t type) {
	struct arp_entry *iter = arp_find(ip);
	const struct rte_ether_addr zero = {.addr_bytes = {0}};
	if (iter != NULL) { // 找到ip对应条目，更新
		if (rte_is_same_ether_addr(&mac, &iter->mac) || rte_is_same_ether_addr(&mac, &zero)) {
			return;
		}
		rte_ether_addr_copy(&mac, &iter->mac);
		iter->type = type;

		return;
	}

	// 新增arp条目
	iter = rte_malloc("ARP entry", sizeof(struct arp_entry), 0);
	if (iter == NULL) {
		rte_exit(EXIT_FAILURE, "Error: rte_malloc arp entry failed.\n");
	}

	iter->ip = ip;
	rte_ether_addr_copy(&mac, &iter->mac);
	iter->type = type;

	struct arp_table *arp_tbl = get_arp_table();

	iter->next = arp_tbl->entries;
	arp_tbl->entries = iter;
	arp_tbl->count += 1;

	return;
}

void arp_show() {
	struct arp_entry *iter = get_arp_table()->entries;
	char macfmt[RTE_ETHER_ADDR_FMT_SIZE] = {0};
	struct in_addr addr;
	
	printf("[ARP table]%d items.\n", get_arp_table()->count);
	while (iter) {
		addr.s_addr = iter->ip;
		rte_ether_format_addr(macfmt, RTE_ETHER_ADDR_FMT_SIZE, &iter->mac);
		printf("[ARP table]ip: %s --- mac: %s --- type: %s\n", inet_ntoa(addr), macfmt, arp_type[iter->type]);

		iter = iter->next;
	}
}


