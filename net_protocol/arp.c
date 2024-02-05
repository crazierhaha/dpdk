#include "arp.h"

#include <rte_malloc.h>
#include <arpa/inet.h>

const char *arp_type[2] = {"Static", "Dynamic"};

static struct arp_table *g_arp_table = NULL;
static const struct rte_ether_addr g_default_dst_mac = { .addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} };

void arp_init(uint16_t port_id) {
	if (g_arp_table != NULL) {
		return;
	}
	printf("[arp]init: create arp table.\n");
	g_arp_table = rte_malloc("ARP table", sizeof(struct arp_table), 0);
	if (g_arp_table == NULL) {
		rte_exit(EXIT_FAILURE, "Error: rte_malloc arp table failed.\n");
	}
	g_arp_table->entries = NULL;
	g_arp_table->count = 0;

	// 维护本地网卡的mac和ip到arp table
	g_arp_table->localIp = MAKE_IPV4_ADDR(192, 168, 3, 222);
	rte_eth_macaddr_get(port_id, &g_arp_table->localMac);
}

static inline struct arp_table *get_arp_table(void) {
	return g_arp_table;
}

struct arp_entry *arp_find(uint32_t ip) {
	struct arp_entry *iter = get_arp_table()->entries;

	while (iter) {
		if (iter->ip == ip) {
			return iter;
		}
		iter = iter->next;
	}

	return NULL;
}

void arp_add_entry(uint32_t ip, struct rte_ether_addr mac, uint8_t type) {
	struct arp_entry *iter = arp_find(ip);
	if (iter != NULL) { // 更新
		const struct rte_ether_addr zero_addr = { .addr_bytes = {0} };
		if (rte_is_same_ether_addr(&mac, &iter->mac) || rte_is_same_ether_addr(&mac, &zero_addr)) {
			return;
		}

		rte_ether_addr_copy(&mac, &iter->mac);
		iter->type = type;

		return;
	}

	// 新增
	iter = rte_malloc("ARP entry", sizeof(struct arp_entry), 0);
	if (iter == NULL) {
		rte_exit(EXIT_FAILURE, "Error: rte_malloc arp entry failed.\n");
	}

	iter->ip = ip;
	rte_ether_addr_copy(&mac, &iter->mac);
	iter->type = type;

	struct arp_table *tbl = get_arp_table();

	iter->next = tbl->entries;
	tbl->entries = iter;
	tbl->count += 1;

	return;
}

/* 封装   arp 包 */
struct rte_mbuf *arp_pkt_creator(struct rte_mempool *tx_mbuf_pool, uint16_t opcode,
									   const struct rte_ether_addr * const src_mac, const struct rte_ether_addr * const dst_mac,
									   uint32_t sip, uint32_t dip) {
	// 创建并处理mbuf
	struct rte_mbuf *arp_mbuf = rte_pktmbuf_alloc(tx_mbuf_pool);
	if (arp_mbuf == NULL) {
		rte_exit(EXIT_FAILURE, "Error: arp_pkt_creator::rte_pktmbuf_alloc\n");
	}

	uint32_t pkt_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	arp_mbuf->pkt_len = pkt_length;
	arp_mbuf->data_len = pkt_length;

	// encode arp 包
	// 1. ether
	struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(arp_mbuf, struct rte_ether_hdr *);
	rte_ether_addr_copy(src_mac, &ethhdr->s_addr);
	rte_ether_addr_copy(dst_mac, &ethhdr->d_addr);
	ethhdr->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2. arp
	struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethhdr + 1);
	arphdr->arp_hardware = htons(1);
	arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arphdr->arp_hlen = RTE_ETHER_ADDR_LEN; // ether协议长度
	arphdr->arp_plen = sizeof(uint32_t); // IPv4
	arphdr->arp_opcode = htons(opcode); // 1 request / 2 response

	rte_ether_addr_copy(src_mac, &arphdr->arp_data.arp_sha);
	if (rte_is_same_ether_addr(dst_mac, &g_default_dst_mac)) {
		struct rte_ether_addr zero_mac = { .addr_bytes = { 0x0 } };
		rte_ether_addr_copy(&zero_mac, &arphdr->arp_data.arp_tha);
	} else {
		rte_ether_addr_copy(dst_mac, &arphdr->arp_data.arp_tha);
	}

	arphdr->arp_data.arp_sip = sip;
	arphdr->arp_data.arp_tip = dip;

	return arp_mbuf;
}

void arp_show(void) {
	struct arp_entry *iter = get_arp_table()->entries;
	char macfmt[RTE_ETHER_ADDR_FMT_SIZE] = {0};
	struct in_addr addr;

	printf("[ARP table]%d items.\n", get_arp_table()->count);
	addr.s_addr = get_arp_table()->localIp;
	rte_ether_format_addr(macfmt, RTE_ETHER_ADDR_FMT_SIZE, &get_arp_table()->localMac);
	printf("[ARP table]local: ip:%s --- mac:%s\n", inet_ntoa(addr), macfmt);   
	while (iter && !g_exit_flag) {
		addr.s_addr = iter->ip;
		rte_ether_format_addr(macfmt, RTE_ETHER_ADDR_FMT_SIZE, &iter->mac);
		printf("  [ARP item]ip: %s --- mac: %s --- type: %s\n", inet_ntoa(addr), macfmt, arp_type[iter->type]);
		iter = iter->next;
	}
}

// ARP request 定时器发包的回调函数
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {
	struct rte_mempool *tx_mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ringInst = ringInstance();

	unsigned lcore_id = rte_lcore_id();
	printf("%s() on lcore %u\n", __func__, lcore_id);
	arp_show();

	const uint32_t localIp = get_arp_table()->localIp;
	struct rte_ether_addr localMac;
	rte_ether_addr_copy(&get_arp_table()->localMac, &localMac);
	// 遍历局域网所有IP
	for (uint32_t i = 1; i < 255; i++) {
		uint32_t dip = (localIp & 0xFFFFFF) | (0xFF000000 & (i << 24));
		struct rte_mbuf *tx_arp_mbuf = NULL;

		struct arp_entry *arp = arp_find(dip);
		if (arp) {
			tx_arp_mbuf = arp_pkt_creator(tx_mbuf_pool, RTE_ARP_OP_REQUEST, &localMac, &arp->mac, localIp, dip);
		} else {
			tx_arp_mbuf = arp_pkt_creator(tx_mbuf_pool, RTE_ARP_OP_REQUEST, &localMac, &g_default_dst_mac, localIp, dip);
		}

		// DEBUG
		if (0) {
			printf("[callback]datalen=%d\n", tx_arp_mbuf->data_len);
		}

		// tx mbuf 入队
		rte_ring_mp_enqueue_burst(ringInst->out, (void **)&tx_arp_mbuf, 1, NULL);
	}

	return;
}

void kr_arp_procedure(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool) {
	// 0. arp header
	struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(in_mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
	
	// 1. 过滤非本机arp报文
	if (arp_hdr->arp_data.arp_tip != get_arp_table()->localIp) {
		return;
	}

	// 2. 判断Reply和Request报文
	if (rte_cpu_to_be_16(RTE_ARP_OP_REPLY) == arp_hdr->arp_opcode) {
		// 1. 取arp中的srcip和srcmac
		uint32_t sip = arp_hdr->arp_data.arp_sip;
		struct rte_ether_addr sha;
		rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &sha);

		// 3. 增加arp条目
		arp_add_entry(sip, sha, 1);
	} else if (rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) == arp_hdr->arp_opcode) {
		struct inout_ring *ringInst = ringInstance();
	
		// 4. 创建 ARP Reply 包
		struct rte_mbuf *tx_arp_mbuf = NULL;
		
		tx_arp_mbuf = arp_pkt_creator(tx_mbuf_pool, RTE_ARP_OP_REPLY,
				&get_arp_table()->localMac, &arp_hdr->arp_data.arp_tha, get_arp_table()->localIp, arp_hdr->arp_data.arp_tip);
		
		// 5. ARP Reply 包入队 ring->out
		rte_ring_mp_enqueue_burst(ringInst->out, (void **)&tx_arp_mbuf, 1, NULL);
	}
}



