#include "ipv4_worker.h"
#include "icmp.h"

#include <rte_ethdev.h>

#include <arpa/inet.h>

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

	// 判断是 UDP 还是 TCP 还是 ICMP
	if (ipv4hdr->next_proto_id == IPPROTO_UDP) {
		printf("[%s]UDP protocol is not supported.\n", __func__);
		return;
	}

	if (ipv4hdr->next_proto_id == IPPROTO_TCP) {
		printf("[%s]TCP protocol is not supported.\n", __func__);
		return;
	}

	if (ipv4hdr->next_proto_id == IPPROTO_ICMP) {
		kr_icmp_worker(in_mbuf, tx_mbuf_pool);
		return;
	}
}

