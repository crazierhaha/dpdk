#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_mbuf.h>

#include <pcap.h>
#include <sys/time.h>

#include <time.h>

#define KR_MBUF_SIZE (4096-1)
#define KR_MBUF_CACHE_SIZE 250
#define MAX_PKT_BURST 32
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512

// 全局变量定义
static volatile uint8_t g_bForce_quit;
static uint16_t g_nCap_port;
static const struct rte_eth_conf g_default_rte_eth_conf = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};
// pcap 相关定义
pcap_dumper_t *g_dumper = NULL;

static void
openFile(const char *file_name) {
	g_dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 1600), file_name);
	if (g_dumper == NULL) {
		printf("dumper file is NULL.\n");
		return;
	}
}

static void
dumpFile(const uint8_t *pkt, int len, time_t tv_sec, suseconds_t tv_usec) {
	struct pcap_pkthdr pcap_hdr;
	pcap_hdr.ts.tv_sec = tv_sec;
	pcap_hdr.ts.tv_usec = tv_usec;
	pcap_hdr.caplen = len;
	pcap_hdr.len = len;

	pcap_dump((uint8_t *)g_dumper, &pcap_hdr, pkt);
}

static void print_stats(void) {
	struct rte_eth_stats stats;
	printf("\nStatistics for port %d\n", g_nCap_port);
	rte_eth_stats_get(g_nCap_port, &stats);
	printf("RX:%9"PRIu64" TX:%9"PRIu64" dropped:%9"PRIu64"\n",
		stats.ipackets, stats.opackets, stats.imissed);
}

static void signal_handler(int sig_num) {
	if (sig_num == SIGINT || sig_num == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", sig_num);
		g_bForce_quit = 1;
	
		// 打印统计信息
		print_stats();
	}
}

static void kr_init_port(uint16_t port, struct rte_mempool *mbuf_pool) {
	// 参数定义
	int ret;
	const uint16_t nb_rx_queues = 1;
	const uint16_t nb_tx_queues = 0;
	struct rte_eth_conf port_conf = g_default_rte_eth_conf;

	// 判断端口是否合法
	uint16_t nb_ports = rte_eth_dev_count_avail();
	if (port >= nb_ports) {
		rte_exit(EXIT_FAILURE, "Error: invalid port input.\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	}

	// 配置网卡
	ret = rte_eth_dev_configure(port, nb_rx_queues, nb_tx_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: rte_eth_dev_configure failed.\n");
	}

	uint16_t rx_slots, tx_slots;
	/** Check that numbers of Rx and Tx descriptors satisfy descriptors limits from the Ethernet device information, 
	 *  otherwise adjust them to boundaries. */
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_slots, &tx_slots);

	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: Couldn't ot adjust number of descriptors for port %u\n", port);
	}

	// 配置网卡收包队列
	ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: could not setup rx queue\n");
	}

	// 启动网卡设备
	ret = rte_eth_dev_start(port);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: could not start\n");
	}

	// 开启混杂模式
	rte_eth_promiscuous_enable(port);
}

static int
lcore_main(__attribute__((unused)) void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("thread from core %u\n", lcore_id);

	// 1. 创建pcap文件
	time_t t_now = time(NULL);
	struct tm tm_now = *(localtime(&t_now));
	if (g_dumper == NULL) {
		char dump_name[256] = {0};
		snprintf(dump_name, 256, "%d%d%d.pcap", tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);

		openFile(dump_name);
	}

	while (!g_bForce_quit) {
		uint16_t kr_nb_recv;
		// 1. 创建mbuf
		struct rte_mbuf *mbufs[MAX_PKT_BURST];
		kr_nb_recv = rte_eth_rx_burst(g_nCap_port, 0, mbufs, MAX_PKT_BURST);

		if (unlikely(kr_nb_recv == 0)) { // unlikely - 分支预测
			continue;
		}

		for (int i = 0; i < kr_nb_recv; i++) {
			struct timeval tv;
			gettimeofday(&tv, NULL);

			uint8_t *pkt = rte_pktmbuf_mtod(mbufs[i], uint8_t *);
			dumpFile(pkt, mbufs[i]->data_len, tv.tv_sec, tv.tv_usec);
		}
	}
	
	printf("lcore %u exiting\n", lcore_id);
	
	return 0;
}


int main(int argc, char **argv) {
	// 0. 参数定义
	int ret;
	struct rte_mempool *kr_mbuf_pool;

	// 1. 注册中断信号处理函数
	g_bForce_quit = 0;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// 2. 初始化eal
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: EAL init failed.\n");
	}

	// 打印可用网口信息
	uint8_t nb_ports = rte_eth_dev_count_avail();
	for (uint16_t i = 0; i < nb_ports; i++) {
		char dev_name[RTE_DEV_NAME_MAX_LEN];
		rte_eth_dev_get_name_by_port(i, dev_name);
		printf("Number %d: %s ", i, dev_name);

		struct rte_ether_addr mac_addr;
		rte_eth_macaddr_get(i, &mac_addr);

		char mac_fmt[RTE_ETHER_ADDR_FMT_SIZE] = {0};
		rte_ether_format_addr(mac_fmt, RTE_ETHER_ADDR_FMT_SIZE, (const struct rte_ether_addr *)&mac_addr);
		printf("mac: %s\n", mac_fmt);
	}

	printf("Choose a port, enter ther port number: \n");
	scanf("%d", &g_nCap_port);

	// 3. 申请内存池
	kr_mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", KR_MBUF_SIZE * nb_ports, KR_MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (kr_mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Error: mempool create failed.\n");
	}

	// 4. 初始化网卡
	kr_init_port(g_nCap_port, kr_mbuf_pool);

	// 5. 线程核心绑定，循环处理数据包
	rte_eal_mp_remote_launch(lcore_main, NULL, 0); // 0 - SKIP_MASTER
	rte_eal_mp_wait_lcore();

	return 0;
}
