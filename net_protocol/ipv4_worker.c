#include "ipv4_worker.h"

#include <rte_ethdev.h>

#include <arpa/inet.h>

#include "icmp.h"
#include "arp.h"
#include "kr_tcp.h"

void kr_ipv4_procedure(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool) {
	struct rte_ipv4_hdr *ipv4hdr = rte_pktmbuf_mtod_offset(in_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	// DEBUG
	if (1) {
		struct in_addr addr;
		addr.s_addr = ipv4hdr->src_addr;
		printf("[IPv4](%s --> ", inet_ntoa(addr));
		addr.s_addr = ipv4hdr->dst_addr;
		printf("%s), ", inet_ntoa(addr));
	}

	if (ipv4hdr->next_proto_id == IPPROTO_ICMP) {
		kr_icmp_worker(in_mbuf, tx_mbuf_pool);
		return;
	}

	// 过滤目的地址非本网卡的 TCP/UDP 包
	if (arp_get_local_ip() != ipv4hdr->dst_addr) {
		return;
	}

	// 判断是 UDP 还是 TCP 还是 ICMP
	if (ipv4hdr->next_proto_id == IPPROTO_UDP) {
		printf("[%s]UDP protocol is not supported.\n", __func__);
		return;
	}

	if (ipv4hdr->next_proto_id == IPPROTO_TCP) {
		kr_tcp_procedure(in_mbuf, tx_mbuf_pool);
		// printf("[%s]TCP protocol is not supported.\n", __func__);
		return;
	}
}

static int set_mbuf_mac(struct rte_mbuf *tx_mbuf, struct rte_mempool *tx_mbuf_pool) {
debug_start();
	struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod_offset(tx_mbuf, struct rte_ether_hdr *, 0);
	struct rte_ipv4_hdr *ipv4hdr = rte_pktmbuf_mtod_offset(tx_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	uint32_t sip = ipv4hdr->src_addr;
	uint32_t dip = ipv4hdr->dst_addr;

	// 源IP/MAC
	struct rte_ether_addr *localMac = arp_get_local_mac();
	uint32_t localIp = arp_get_local_ip();
	if (localIp != sip) {
		printf("[%s]Error: source ip is not matched to arp table.\n", __func__);
		return -1;
	}

	// 目的IP/MAC
	struct rte_ether_addr *dest_mac = arp_get_mac_with_ip(dip, tx_mbuf_pool);
	if (dest_mac == NULL) {
		printf("[%s]Warning: there is no mac addr for ip[%d], arp requesting.\n", __func__, dip);
		return -1;
	}

	rte_ether_addr_copy(localMac, &ethhdr->s_addr);
	rte_ether_addr_copy(dest_mac, &ethhdr->d_addr);
	ethhdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
debug_end();
	return 0;
}

void tcp_send(struct rte_mempool *tx_mbuf_pool) {
	struct inout_ring *ring = ringInstance();
	struct kr_tcp_table *tcp_table = get_tcp_table();

	struct kr_tcp_entry *iter = NULL;
	for (iter = tcp_table->entries; iter != NULL; iter = iter->next) {
		if (iter->tcp_stream.sndring == NULL) {
			continue;
		}

		struct rte_mbuf *tx_mbufs[TXRX_BURST_SIZE];
		//int nb_snd = rte_ring_mc_dequeue(iter->tcp_stream.sndring, (void **)tx_mbufs);
		int nb_snd =rte_ring_mc_dequeue_burst(iter->tcp_stream.sndring, (void **)tx_mbufs, TXRX_BURST_SIZE, NULL);
		if (nb_snd <= 0) {
			continue;
		}

		// printf("[%s]%d tcp pkt send.\n", __func__, nb_snd);

		for (int i = 0; i < nb_snd; i++) {
			int ret = set_mbuf_mac(tx_mbufs[i], tx_mbuf_pool);
			if (ret == 0) {
				print_head(__func__, tx_mbufs[0]);
				rte_ring_mp_enqueue_burst(ring->out, (void **)&tx_mbufs[i], 1, NULL);
			} else {
				rte_ring_mp_enqueue(iter->tcp_stream.sndring, tx_mbufs[i]);
			}
		}
	}
}

