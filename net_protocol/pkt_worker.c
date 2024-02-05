#include "pkt_worker.h"

#include <stdio.h>
#include <stdint.h>

#include <rte_mbuf.h>
#include <rte_branch_prediction.h>
#include <rte_ethdev.h>

#include "arp.h"
#include "ipv4_worker.h"


// 分发处理各种协议包
int pkt_worker(void *arg) {
	struct rte_mempool *tx_mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

	while (!g_exit_flag) {
		// 1. 从 ring 中取mbuf
		struct rte_mbuf *in_mbufs[TXRX_BURST_SIZE];
		unsigned nb_in = rte_ring_mc_dequeue_burst(ring->in, (void **)in_mbufs, TXRX_BURST_SIZE, NULL);

		// DEBUG
		if (0) {
			if (nb_in > 0) {
				printf("[DEBUG][%s]%d pkts were received.\n", __func__, nb_in);
			}
		}

		for (unsigned i = 0; i < nb_in; i++) {
			struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(in_mbufs[i], struct rte_ether_hdr *);

			// DEBUG
			if (0) {
				char macfmt[RTE_ETHER_ADDR_FMT_SIZE] = {0};
				rte_ether_format_addr(macfmt, RTE_ETHER_ADDR_FMT_SIZE, &ethhdr->s_addr);
				printf("[DEBUG]pkt in: mac:%s\n", macfmt);
			}

			// 首先区分 IP、ARP、RARP 等协议包
			if (likely(rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) == ethhdr->ether_type)) {
				// 处理IPv4报文的逻辑
				kr_ipv4_procedure(in_mbufs[i], tx_mbuf_pool);
			} else if (rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP) == ethhdr->ether_type) {
				// 处理ARP报文的逻辑
				kr_arp_procedure(in_mbufs[i], tx_mbuf_pool);
			} else if (rte_cpu_to_be_16(RTE_ETHER_TYPE_RARP) == ethhdr->ether_type) {
				// TODO: 处理RARP报文的逻辑
				printf("[Warning]RARP protocol is not supported.\n");
			} else if (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6) == ethhdr->ether_type) {
				// TODO: 处理IPv6报文的逻辑
			} else {
				printf("[Warning]IPv6 protocol is not supported.\n");
			}

			rte_pktmbuf_free(in_mbufs[i]);
		}
	}

	return 0;
}



