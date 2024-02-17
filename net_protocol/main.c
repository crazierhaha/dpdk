#include <stdio.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include <signal.h>
#include <arpa/inet.h>

#include "common.h"
#include "arp.h"
#include "pkt_worker.h"
#include "kr_socket.h"

// DEBUG
void print_mac(struct rte_ether_addr *mac) {
	char macdebug[RTE_ETHER_ADDR_FMT_SIZE] = {0};
	rte_ether_format_addr(macdebug, RTE_ETHER_ADDR_FMT_SIZE, mac);
	printf("%s ", macdebug);
}

// 宏定义
/* 配置  TX/RX ring 描述符的数量 */
#define RX_DESC_NB_DEFAULT 1024
#define TX_DESC_NB_DEFAULT 1024
static uint16_t l_nb_rxd = RX_DESC_NB_DEFAULT;
static uint16_t l_nb_txd = TX_DESC_NB_DEFAULT;

// ARP request 定时器的时间间隔
#define TIMER_RESOLUTION_CYCLES 120000000000ULL /* around 10ms at 2 Ghz(20000000ULL) */

// 全局变量定义
volatile int g_exit_flag = 0;
static const uint16_t g_iPort_id = 0;
static struct rte_eth_conf g_default_port_conf = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};


// 简单单例模式
struct inout_ring *ringInstance(void) {
	static struct inout_ring *ringInst = NULL;
	if (ringInst == NULL) {
		printf("ring initialization.\n");
		ringInst = rte_malloc_socket("in/out ring", sizeof(struct inout_ring), 0, rte_socket_id());
		if (ringInst == NULL) {
			rte_exit(EXIT_FAILURE, "Error: rte_malloc ring instance failed.\n");
		}
		ringInst->in = rte_ring_create("pkt in ring", TXRX_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
		if (ringInst->in == NULL) {
			rte_free(ringInst);
			rte_exit(EXIT_FAILURE, "Error: rte_ring_create in ring failed.\n");
		}
		ringInst->out = rte_ring_create("pkt out ring", TXRX_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
		if (ringInst->out == NULL) {
			rte_ring_free(ringInst->in);
			rte_free(ringInst);
			rte_exit(EXIT_FAILURE, "Error: rte_ring_create out ring failed.\n");
		}
	}
	return ringInst;
}

static void
signal_handler(int signum) {
	printf("\nSignal %d received\n", signum);
	g_exit_flag = 1;
}

static void kr_port_init(uint16_t port_id, struct rte_mempool *mbuf_pool) {
	// 参数定义
	int ret;
	const uint16_t nb_rx_queues = 1;
	const uint16_t nb_tx_queues = 1;
	struct rte_eth_conf port_conf = g_default_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;


	printf("Initializing port %u...\n", port_id);

	// 获取 eth 信息
	rte_eth_dev_info_get(port_id, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	}

	// 设置 tx/rx 队列的数量
	ret = rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: Cannot configure device: err=%d, port=%u\n", ret, port_id);
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &l_nb_rxd, &l_nb_txd);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: Cannot adjust number of descriptors: err=%d, port=%u\n", ret, port_id);
	}

	// 为 eth 分配和设置接收队列
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port_id, 0, l_nb_rxd, rte_eth_dev_socket_id(port_id), &rxq_conf, mbuf_pool);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, port_id);
	}

	// 为 eth 分配和设置发送队列
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port_id, 0, l_nb_txd, rte_eth_dev_socket_id(port_id), &txq_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, port_id);
	}

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: rte_eth_dev_start:err=%d, port=%u\n", ret, port_id);
	}
	printf("Initializing port %u success.\n", port_id);
}

// app worker
static int tcp_app_worker(__attribute__((unused)) void *arg) {
	// DEBUG
	{
		printf("[%s]Start.\n", __func__);
	}
	int ret;
	int fd = kr_socket(0, SOCK_STREAM, 0);
	if (fd < 0)  {
		printf("[%s]Error: tcp socket failed.\n", __func__);
		return -1;
	}

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(9999);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ret = kr_bind(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
	if (ret < 0) {
		printf("[%s]Error: tcp bind failed.\n", __func__);
		return -1;
	}

	kr_listen(fd, 10);

	int connfd = kr_accept(fd, NULL, NULL);
	printf("[%s]connfd[%d]\n", __func__, connfd);
	if (connfd < 0) {
		return -1;
	}

	sleep(100000);
	// DEBUG
	{
		printf("[%s]End.\n", __func__);
	}

	return 0;
}

int main(int argc, char *argv[]) {
	// 变量定义
	int ret;

	// 初始化 EAL
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: rte_eal_init:err=%d\n", ret);
	}

	g_exit_flag = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// 创建用于 tx/rx mempool
	struct rte_mempool *rx_mbuf_pool = rte_pktmbuf_pool_create("rx mbuf pool", TXRX_MBUF_SIZE, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (rx_mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Error: rx mbuf pool create failed.\n");
	}

	struct rte_mempool *tx_mbuf_pool = rte_pktmbuf_pool_create("tx mbuf pool", TXRX_MBUF_SIZE, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (tx_mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Error: tx mbuf pool create failed.\n");
	}

	// 以太网设备初始化
	// RTE_ETH_FOREACH_DEV(port_id) {
	//     kr_port_init(port_id, rx_mbuf_pool);
	// }
	kr_port_init(g_iPort_id, rx_mbuf_pool);

	// 初始化 txrx ring
	struct inout_ring *ringInst = ringInstance();

	// 初始化 arp table
	arp_init(g_iPort_id);

	// arp request 定时器初始化
	rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	// TODO1: arp_request_timer_cb
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, tx_mbuf_pool);

	// 报文处理线程
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	// TODO: 多个协议处理线程
	rte_eal_remote_launch(pkt_worker, tx_mbuf_pool, lcore_id);

	// 模拟app处理线程
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	// TODO: 用户使用 tcp 接口线程
	rte_eal_remote_launch(tcp_app_worker, NULL, lcore_id);

	uint64_t prev_tsc = 0, cur_tsc, diff_tsc;

	// TODO2: 多个网卡场景。针对每个网卡设置一个收发包线程
	while (1) {
		if (g_exit_flag == 1) {
			break;
		}

		// rx
		unsigned nb_recv;
		struct rte_mbuf *rx_mbuf[TXRX_BURST_SIZE];

		// TODO: 增加统计收包数据
		nb_recv = rte_eth_rx_burst(g_iPort_id, 0, rx_mbuf, TXRX_BURST_SIZE);
		if (nb_recv) {
			// 将收到的 rx_mbuf 入队到 ringInst->in
			// TODO3: 增加统计包 enqueue miss 数据
			// TODO4: 增加多网卡收包场景的多生产者模式
			unsigned nb_rx = rte_ring_sp_enqueue_burst(ringInst->in, (void **)rx_mbuf, nb_recv, NULL);
			// DEBUG
			if (0) {
				printf("[DEBUG][%s]%d pkts were received.\n", __func__, nb_rx);
			}
		}

		// tx
		unsigned nb_send;
		struct rte_mbuf *tx_mbufs[TXRX_BURST_SIZE];
		// TODO5: 增加多网卡发包场景的多消费者模式
		nb_send = rte_ring_mc_dequeue_burst(ringInst->out, (void **)tx_mbufs, TXRX_BURST_SIZE, NULL);
		if (nb_send) {
			print_head(__func__, tx_mbufs[0]);
			// TODO: 增加统计发包数据
			uint16_t nb_tx = rte_eth_tx_burst(g_iPort_id, 0, tx_mbufs, nb_send);

			// DEBUG
			if (0) {
				printf("[DEBUG][%s]%d pkts were tx.\n", __func__, nb_tx);
			}

			// 此处需要释放掉out队列中传过来的 mbuf
			for (unsigned i = 0; i < nb_send; i++) {
				rte_pktmbuf_free(tx_mbufs[i]);
			}
		}

		// arp request 定时器判断及出发
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}

}
