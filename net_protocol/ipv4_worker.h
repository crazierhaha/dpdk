#ifndef __IPV4_WORKER__
#define __IPV4_WORKER__

#include <rte_malloc.h>
#include <rte_mbuf.h>

void kr_ipv4_procedure(struct rte_mbuf *in_mbuf, struct rte_mempool *tx_mbuf_pool);
void tcp_send(struct rte_mempool *tx_mbuf_pool);


#endif // __IPV4_WORKER__
