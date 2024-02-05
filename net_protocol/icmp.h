#ifndef __ICMP__
#define __ICMP__

#include <rte_mbuf.h>

void kr_icmp_worker(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool);

#endif // __ICMP__
