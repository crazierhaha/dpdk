#include <stdio.h>
#include <stdint.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <arpa/inet.h>

#include "arp.h"

#define KR_MBUF_SIZE (4096-1)
#define KR_MBUF_CACHE_SIZE 250
#define MAX_PKT_BURST 32

static int gDpdkKrPortId = 0;

#define ENABLE_DEBUG    1

#define ENABLE_SEND		1
#define ENABLE_ARP      1
#define ENABLE_TCP      0
#define ENABLE_ICMP     1
#define ENABLE_UDP      1

#define ENABLE_ARP_TABLE 1

#define TIMER_RESOLUTION_CYCLES 20000000000ULL /* around 10ms at 2 Ghz */

// 设置本地网卡静态IP: 192.168.0.222
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIP = MAKE_IPV4_ADDR(192, 168, 3, 222);

static const uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#if ENABLE_SEND

static uint32_t kr_src_ip, kr_dst_ip;
static uint16_t kr_src_port, kr_dst_port;
uint8_t kr_src_mac[RTE_ETHER_ADDR_LEN];
uint8_t kr_dst_mac[RTE_ETHER_ADDR_LEN];

#endif

static const struct rte_eth_conf default_rte_eth_conf = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void kr_init_port(struct rte_mempool *mbuf_pool) {
	int ret;
	// 设置tx/rx队列数量
	const uint16_t num_rx_queues = 1;
	const uint16_t num_tx_queues = 1;
	struct rte_eth_conf port_conf = default_rte_eth_conf;

	rte_eth_dev_configure(gDpdkKrPortId, num_rx_queues, num_tx_queues, &port_conf);

	// 启动rx队列
	ret = rte_eth_rx_queue_setup(gDpdkKrPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkKrPortId), NULL, mbuf_pool);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: could not setup rx queue\n");
	}

#if ENABLE_SEND
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkKrPortId, &dev_info);
	struct rte_eth_txconf tx_conf_q = dev_info.default_txconf;
	tx_conf_q.offloads = port_conf.rxmode.offloads;
	ret = rte_eth_tx_queue_setup(gDpdkKrPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkKrPortId), &tx_conf_q);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: could not setup tx queue\n");
	}
#endif

	ret = rte_eth_dev_start(gDpdkKrPortId);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: could not start\n");
	}
}

static void kr_encode_udp_pkt(uint8_t *msg, uint8_t *data, uint16_t total_len) {
	// 1. ethhdr
	struct rte_ether_hdr *ehdr = (struct rte_ether_hdr *)msg;
	rte_memcpy(ehdr->s_addr.addr_bytes, kr_src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(ehdr->d_addr.addr_bytes, kr_dst_mac, RTE_ETHER_ADDR_LEN);
	ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2. iphdr
	struct rte_ipv4_hdr *ipv4hdr = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ipv4hdr->version_ihl = 0x45;
	ipv4hdr->type_of_service = 0;
	ipv4hdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ipv4hdr->packet_id = 0;
	ipv4hdr->fragment_offset = 0;
	ipv4hdr->time_to_live = 64; // TTL
	ipv4hdr->next_proto_id = IPPROTO_UDP;
	ipv4hdr->src_addr = kr_src_ip;
	ipv4hdr->dst_addr = kr_dst_ip;
	ipv4hdr->hdr_checksum = 0;
	ipv4hdr->hdr_checksum = rte_ipv4_cksum(ipv4hdr);

	// 3. udphdr
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udphdr->src_port = kr_src_port;
	udphdr->dst_port = kr_dst_port;
	uint16_t udplen = htons(total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));
	udphdr->dgram_len = htons(udplen);

	rte_memcpy((uint8_t *)(udphdr + 1), data, total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr));

	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4hdr, udphdr);

	struct in_addr addr;
	addr.s_addr = kr_src_ip;
	printf(" --> src: %s:%d, [%d]", inet_ntoa(addr), ntohs(kr_src_port), total_len);

	addr.s_addr = kr_dst_ip;
	printf("dst: %s:%d [%s]\n", inet_ntoa(addr), ntohs(kr_dst_port), (char *)data);

	return;
}

static void kr_udp_procedure(struct rte_udp_hdr *udphdr, struct rte_mempool *mbuf_pool) {
	(void)mbuf_pool; // for clean code
	
#if ENABLE_UDP
	
	uint16_t length = ntohs(udphdr->dgram_len);
	*((char *)udphdr + length) = '\0';
	printf("[udp](%d --> %d), data: [%s]\n", ntohs(udphdr->src_port), ntohs(udphdr->dst_port), (char *)(udphdr + 1));

#else

	printf("[Warning][IPv4]UDP protocol is not supported.\n");

#endif

}

static void kr_tcp_procedure(struct rte_tcp_hdr *tcphdr, struct rte_mempool *mbuf_pool) {
	(void)tcphdr;
	(void)mbuf_pool; // for clean code
#if ENABLE_TCP
	// TODO
#else
	printf("[Warning][IPv4]TCP protocol is not supported.\n");
#endif
}

#if ENABLE_ICMP

static uint16_t icmp_chsum(uint16_t *addr, int count) {
	register long sum = 0;

	while (count > 1) {
		sum += *(uint16_t *)addr++;
		count -= 2;
	}
	if (count > 0) {
		sum += *(uint8_t *)addr;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

#endif

static void kr_icmp_procedure(struct rte_mbuf *rxbuf, struct rte_mempool *mbuf_pool) {

#if ENABLE_ICMP
	// 创建发包的mbuf
	struct rte_mbuf *txbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (NULL == txbuf) {
		rte_exit(EXIT_FAILURE, " Error: rte_pktmbuf_alloc\n");
	}

	// 1. ether
	uint32_t total_length = sizeof(struct rte_ether_hdr);
	
	struct rte_ether_hdr *src_ethhdr = rte_pktmbuf_mtod_offset(rxbuf, struct rte_ether_hdr *, 0);
	struct rte_ether_hdr *dst_ethhdr = rte_pktmbuf_mtod_offset(txbuf, struct rte_ether_hdr *, 0);

	rte_memcpy(dst_ethhdr->s_addr.addr_bytes, src_ethhdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	rte_memcpy(dst_ethhdr->d_addr.addr_bytes, src_ethhdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	dst_ethhdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2. ip
	struct rte_ipv4_hdr *src_iphdr = rte_pktmbuf_mtod_offset(rxbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_ipv4_hdr *dst_iphdr = rte_pktmbuf_mtod_offset(txbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	dst_iphdr->version_ihl = 0x45;
	dst_iphdr->type_of_service = 0;
	dst_iphdr->total_length = src_iphdr->total_length;
	dst_iphdr->packet_id = 0;
	dst_iphdr->fragment_offset = 0;
	dst_iphdr->time_to_live = 64;
	dst_iphdr->next_proto_id = IPPROTO_ICMP;
	dst_iphdr->src_addr = src_iphdr->dst_addr;
	dst_iphdr->dst_addr = src_iphdr->src_addr;

	dst_iphdr->hdr_checksum = 0;
	dst_iphdr->hdr_checksum = rte_ipv4_cksum(dst_iphdr);

	total_length += ntohs(src_iphdr->total_length);

	// 3. icmp
	struct rte_icmp_hdr *src_icmphdr =
		rte_pktmbuf_mtod_offset(rxbuf, struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	struct rte_icmp_hdr *dst_icmphdr =
		rte_pktmbuf_mtod_offset(txbuf, struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	dst_icmphdr->icmp_type = 0;
	dst_icmphdr->icmp_code = 0;
	dst_icmphdr->icmp_ident = src_icmphdr->icmp_ident;
	dst_icmphdr->icmp_seq_nb = src_icmphdr->icmp_seq_nb;

	// 填充 icmp 后面的数据
	uint8_t *srcdata = (uint8_t *)(src_icmphdr + 1);
	uint8_t *dstdata = (uint8_t *)(dst_icmphdr + 1);
	rte_memcpy(dstdata, srcdata, total_length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_icmp_hdr));

	dst_icmphdr->icmp_cksum = 0;
	dst_icmphdr->icmp_cksum = icmp_chsum((uint16_t *)dst_icmphdr, total_length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));

	txbuf->data_len = total_length;
	txbuf->pkt_len = total_length;

	// 发包
	rte_eth_tx_burst(gDpdkKrPortId, 0, &txbuf, 1);

	printf("[ICMP]reply done.\n");

	rte_pktmbuf_free(txbuf);
#else

	printf("[Warning][IPv4]ICMP protocol is not supported.\n");

#endif
}

static void kr_IPv4_procedure(struct rte_mbuf *mbuf, struct rte_mempool *mbuf_pool) {
	// 从kr_rte_mbufs中取IPv4报文
	struct rte_ipv4_hdr *src_ipv4hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

#if ENABLE_DEBUG

	struct in_addr addr;
	addr.s_addr = src_ipv4hdr->src_addr;
	printf("[IPv4](%s --> ", inet_ntoa(addr));
	addr.s_addr = src_ipv4hdr->dst_addr;
	printf("%s), ", inet_ntoa(addr));

#endif

	if (IPPROTO_UDP == src_ipv4hdr->next_proto_id) {
		kr_udp_procedure((struct rte_udp_hdr *)(src_ipv4hdr + 1), mbuf_pool);
	} else if (IPPROTO_TCP == src_ipv4hdr->next_proto_id) {
		kr_tcp_procedure((struct rte_tcp_hdr *)(src_ipv4hdr + 1), mbuf_pool);
	} else if (IPPROTO_ICMP  == src_ipv4hdr->next_proto_id) {
		kr_icmp_procedure(mbuf, mbuf_pool);
	} else {
		printf("[Warning][IPv4]No protocol matched.\n");
	}
}

static void kr_encode_arp_pkt(uint8_t *pkt_data, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	// 1. ether
	struct rte_ether_hdr *ethhdr = (struct rte_ether_hdr *)pkt_data;

	uint8_t src_mac[RTE_ETHER_ADDR_LEN];
	rte_eth_macaddr_get(gDpdkKrPortId, (struct rte_ether_addr *)src_mac);
	
	rte_memcpy(ethhdr->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	// 处理 ARP request 的情况
	if (rte_is_same_ether_addr((struct rte_ether_addr *)gDefaultArpMac, (struct rte_ether_addr *)dst_mac)) {
		dst_mac[0] = 0;
		dst_mac[1] = 0;
		dst_mac[2] = 0;
		dst_mac[3] = 0;
		dst_mac[4] = 0;
		dst_mac[5] = 0;
	}
	rte_memcpy(ethhdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	ethhdr->ether_type = htons(RTE_ETHER_TYPE_ARP);
	
	// 2. arp
	struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethhdr + 1);
	arphdr->arp_hardware = htons(1);
	arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arphdr->arp_hlen = RTE_ETHER_ADDR_LEN; // ether协议长度
	arphdr->arp_plen = sizeof(uint32_t); // IPv4
	arphdr->arp_opcode = htons(opcode); // 1 request / 2 response

	rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, kr_src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arphdr->arp_data.arp_sip = sip;
	arphdr->arp_data.arp_tip = dip;

	return;
}

static void kr_arp_procedure(struct rte_mbuf *mbuf, struct rte_mempool *mbuf_pool) {
#if ENABLE_ARP
	// 0. arp header
	struct rte_arp_hdr *kr_arp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
	
	// 0. 过滤非本机arp报文
	if (kr_arp_hdr->arp_data.arp_tip != gLocalIP) {
		return;
	}

	// 判断Reply和Request报文
	if (rte_cpu_to_be_16(RTE_ARP_OP_REPLY) == kr_arp_hdr->arp_opcode) {
		// 1. 取arp中的srcip和srcmac
		uint32_t sip = kr_arp_hdr->arp_data.arp_sip;
		struct rte_ether_addr sha;
		rte_ether_addr_copy(&kr_arp_hdr->arp_data.arp_sha, &sha);

		// 2. 增加arp条目
		arp_add_entry(sip, sha, 1);
	} else if (rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) == kr_arp_hdr->arp_opcode) {
	
		// 1. 创建mbuf
		struct rte_mbuf *arp_mbuf = rte_pktmbuf_alloc(mbuf_pool);
		
		const uint32_t pkt_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
		arp_mbuf->pkt_len = pkt_length;
		arp_mbuf->data_len = pkt_length;
		
		uint8_t *pkt_data = rte_pktmbuf_mtod(arp_mbuf, uint8_t *);
		
		// 2. encode arp
		kr_encode_arp_pkt(pkt_data, RTE_ARP_OP_REPLY, kr_arp_hdr->arp_data.arp_sha.addr_bytes, kr_arp_hdr->arp_data.arp_tip, kr_arp_hdr->arp_data.arp_sip);
		
		// 3. tx pkt
		rte_eth_tx_burst(gDpdkKrPortId, 0, &arp_mbuf, 1);
		
		// 4. clean
		rte_pktmbuf_free(arp_mbuf);
	}
#else
	printf("[Warning]ARP protocol is not supported.\n");
#endif
}

/* timer callback */
static void 
arp_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	  __attribute__((unused)) void *arg)
{
	struct rte_mempool *mpool = (struct rte_mempool *)arg;
	
	unsigned lcore_id = rte_lcore_id();

	printf("%s() on lcore %u\n", __func__, lcore_id);
	arp_show();

	// 发 arp request 消息
	// 1. 创建 mbuf
	struct rte_mbuf *arp_mbuf = rte_pktmbuf_alloc(mpool);
	if (!arp_mbuf) {
		printf("Error: arp timer alloc mbuf failed.\n");
		return;
	}
	const uint32_t length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	arp_mbuf->data_len = length;
	arp_mbuf->pkt_len = length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(arp_mbuf, uint8_t *);
	uint32_t dip;
	struct arp_entry *entry = NULL;
	uint8_t dmac[RTE_ETHER_ADDR_LEN] = {0};
	
	for (uint32_t i = 1; i < 255; i++) {
		dip = (gLocalIP & 0x00FFFFFF) | ((i << 24) & 0xFF000000);

		entry = arp_find(dip);
		if (entry != NULL) {
			rte_memcpy(dmac, entry->mac.addr_bytes, RTE_ETHER_ADDR_LEN);
		} else {
			rte_memcpy(dmac, gDefaultArpMac, RTE_ETHER_ADDR_LEN);
		}
		kr_encode_arp_pkt(pkt_data, RTE_ARP_OP_REQUEST, dmac, gLocalIP, dip);

		// 3. tx pkt
		rte_eth_tx_burst(gDpdkKrPortId, 0, &arp_mbuf, 1);
	}

	// 4. clean
	rte_pktmbuf_free(arp_mbuf);
}


int main(int argc, char *argv[]) {
	// 参数定义
	int ret;
	uint16_t kr_ports;
	struct rte_mempool *kr_mbuf_pool;

	// 1. 初始化EAL
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: init EAL failed\n");
	}

	// 2. 检查可用eth数量
	kr_ports = rte_eth_dev_count_avail();
	if (kr_ports < 1) {
		rte_exit(EXIT_FAILURE, "Error: ports miss\n");
	}

	// 3. 创建内存池
	kr_mbuf_pool = rte_pktmbuf_pool_create("kr mbuf pool", KR_MBUF_SIZE * kr_ports, KR_MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (kr_mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Error: create mbuf pool failed\n");
	}
	
	// 4. 初始化eth
	kr_init_port(kr_mbuf_pool);

	// 5. 获取源mac地址
	rte_eth_macaddr_get(gDpdkKrPortId, (struct rte_ether_addr *)kr_src_mac);

	// 5. arp 定时器初始化
	struct rte_timer arp_timer;
	uint64_t kr_cur_tsc, kr_prev_tsc = 0, kr_diff_tsc;

	/* init RTE timer library */
	rte_timer_subsystem_init();

	/* init timer structures */
	rte_timer_init(&arp_timer);

	/* load arp_timer, every 60 second, on master lcore, reloaded automatically */
	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_timer_cb, kr_mbuf_pool);

	// 创建 arp table
	arp_init();
	
	while (1) {
		uint16_t kr_recv_num;
		struct rte_mbuf *kr_rte_mbufs[MAX_PKT_BURST];
		kr_recv_num = rte_eth_rx_burst(gDpdkKrPortId, 0, kr_rte_mbufs, MAX_PKT_BURST);

		for (int i = 0; i < kr_recv_num; i++) {
			// 从kr_rte_mbufs中取ether报文
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod_offset(kr_rte_mbufs[i], struct rte_ether_hdr *, 0);

			if (rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP) == ehdr->ether_type) {
				// 处理ARP报文的逻辑
				kr_arp_procedure(kr_rte_mbufs[i], kr_mbuf_pool);
			} else if (rte_cpu_to_be_16(RTE_ETHER_TYPE_RARP) == ehdr->ether_type) {
				// TODO: 处理RARP报文的逻辑
				printf("[Warning]RARP protocol is not supported.\n");
			} else if (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) == ehdr->ether_type) {
				// 处理IPv4报文的逻辑
				kr_IPv4_procedure(kr_rte_mbufs[i], kr_mbuf_pool);
			} else if (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6) == ehdr->ether_type) {
				// TODO: 处理IPv6报文的逻辑
			} else {
				printf("[Warning]No protocol matched.\n");
			}

			rte_pktmbuf_free(kr_rte_mbufs[i]);
		}

		kr_cur_tsc = rte_rdtsc();
		kr_diff_tsc = kr_cur_tsc - kr_prev_tsc;
		if (kr_diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			kr_prev_tsc = kr_cur_tsc;
		}
	}

	return 0;
}
