// TODO: icmp 周期性丢包问题

#include "icmp.h"
#include <rte_ethdev.h>

#include "common.h"

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

void kr_icmp_worker(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool) {
	debug_start();
	// 获取收发包队列
	struct inout_ring *ringInst = ringInstance();
	// 创建发包的mbuf
	struct rte_mbuf *out_mbuf = rte_pktmbuf_alloc(tx_mbuf_pool);
	if (NULL == out_mbuf) {
		rte_exit(EXIT_FAILURE, " Error: rte_pktmbuf_alloc\n");
	}

	// 1. ether
	uint32_t total_length = sizeof(struct rte_ether_hdr);

	struct rte_ether_hdr *src_ethhdr = rte_pktmbuf_mtod_offset(in_mbuf, struct rte_ether_hdr *, 0);
	struct rte_ether_hdr *dst_ethhdr = rte_pktmbuf_mtod_offset(out_mbuf, struct rte_ether_hdr *, 0);

	rte_memcpy(dst_ethhdr->s_addr.addr_bytes, src_ethhdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	rte_memcpy(dst_ethhdr->d_addr.addr_bytes, src_ethhdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
	dst_ethhdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2. ip
	struct rte_ipv4_hdr *src_iphdr = rte_pktmbuf_mtod_offset(in_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_ipv4_hdr *dst_iphdr = rte_pktmbuf_mtod_offset(out_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
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
		rte_pktmbuf_mtod_offset(in_mbuf, struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	struct rte_icmp_hdr *dst_icmphdr =
		rte_pktmbuf_mtod_offset(out_mbuf, struct rte_icmp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
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

	out_mbuf->data_len = total_length;
	out_mbuf->pkt_len = total_length;

	// 将 icmp 包放入队列
	rte_ring_mp_enqueue_burst(ringInst->out, (void **)&out_mbuf, 1, NULL);

	printf("[ICMP]reply pkt done.\n");
	debug_end();
}

